// SPDX-License-Identifier: GPL-2.0
/*
 * TDX guest user interface driver
 *
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/set_memory.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/tsm.h>
#include <linux/sizes.h>

#include <uapi/linux/tdx-guest.h>

#include <asm/cpu_device_id.h>
#include <asm/tdx.h>

/*
 * Intel's SGX QE implementation generally uses Quote size less
 * than 8K (2K Quote data + ~5K of certificate blob).
 */
#define GET_QUOTE_BUF_SIZE		SZ_8K

#define GET_QUOTE_CMD_VER		1

/* TDX GetQuote status codes */
#define GET_QUOTE_SUCCESS		0
#define GET_QUOTE_IN_FLIGHT		0xffffffffffffffff

/* TDX service command buffer size */
#define SERVICE_REQ_BUF_LEN		SZ_4K
#define SERVICE_RESP_BUF_LEN		SZ_16K

/* TDX service attestation command buffer header */
#define TDX_ATT_CMD_REQ_SER			0x02
#define TDX_ATT_CMD_OP_COMM			0x01

/* TDX attestation query service operation header */
#define TDX_ATT_OP_ID_QUERY_SERVICE		0x02
#define TDX_ATT_OP_QUERY_VERSION		0x00010000

/* TDX attestation key id service operation header */
#define TDX_ATT_OP_ID_GET_KEY_ID		0x04

/* TDX attestation Quote operation service header */
#define TDX_ATT_OP_ID_QUOTE_REQ			0x05
#define TDX_ATT_OP_QUOTE_REQ_VERSION		0x000000001

/* TDX GetQuote service codes */
#define TDX_ATT_CMD_SERVICE_QUOTE_TIMEOUT	5000

/* struct tdx_quote_buf: Format of Quote request buffer.
 * @version: Quote format version, filled by TD.
 * @status: Status code of Quote request, filled by VMM.
 * @in_len: Length of TDREPORT, filled by TD.
 * @out_len: Length of Quote data, filled by VMM.
 * @data: Quote data on output or TDREPORT on input.
 *
 * More details of Quote request buffer can be found in TDX
 * Guest-Host Communication Interface (GHCI) for Intel TDX 1.0,
 * section titled "TDG.VP.VMCALL<GetQuote>"
 */
struct tdx_quote_buf {
	u64 version;
	u64 status;
	u32 in_len;
	u32 out_len;
	u8 data[];
};

/* Quote data buffer */
static void *quote_data;

/* Lock to streamline quote requests */
static DEFINE_MUTEX(quote_lock);

/*
 * GetQuote request timeout in seconds. Expect that 30 seconds
 * is enough time for QE to respond to any Quote requests.
 */
static u32 getquote_timeout = 30;

/* TDX service command request/response buffers */
static void *req_buf, *resp_buf;

/* GUID to query host services */
static guid_t host_query_guid = GUID_INIT(0x6385c05c, 0xfcc5, 0x41fd, 0xab, 0xd2, 0xfd, 0xca, 0xae, 0xce, 0x97, 0x7d);

/* struct att_cmd_req_buf - Buffer used for attestation related
 * 			    service requests.
 *
 * @hdr: Service hypercall request header.
 * @ver: Command version number.
 * @cmd: Command type.
 * @op: Operation type
 * @rsvd: Reserved for future extension.
 * @op_id: Operation ID.
 * @op_data: Operation data.
 */
struct att_cmd_req_buf {
	struct tdx_service_req_buf hdr;

	/* Command specific header */
	u8 version;
	u8 cmd;
	u8 op;
	u8 rsvd;
	u8 op_id;
	u8 op_data[];
};

/* struct att_cmd_resp_buf - Buffer used for attestation related
 * 			     service response.
 *
 * @hdr: Service hypercall response header.
 * @ver: Command version number.
 * @cmd: Command type.
 * @op: Operation type
 * @rsvd: Reserved for future extension.
 * @op_id: Operation ID.
 * @op_data: Operation data.
 */
struct att_cmd_resp_buf {
	struct tdx_service_resp_buf hdr;

	/* Command specific header */
	u8 version;
	u8 cmd;
	u8 op;
	u8 rsvd;
	u8 op_id;
	u8 op_data[];
};

struct att_cmd_op_query_req {
	u32 version;
	u32 query;
	u8 service_type[8];
};

struct att_cmd_op_query_resp {
	u32 version;
	u32 result;
	u32 result_size;
	u8 guids[];
};

struct att_cmd_op_key_id_req {
	u32 version;
};

struct att_cmd_op_key_id_resp {
	u32 version;
	u32 result;
	u32 result_size;
	u8 guids[];
};

struct att_cmd_op_quote_req {
	u32 version;
	u32 report_size;
	u32 owner_data_size;
	u8 att_key_id[16];
	u8 data[TDX_REPORT_LEN];
};

struct att_cmd_op_quote_resp {
	u32 version;
	u32 result;
	u32 quote_size;
	u8 att_key_id[16];
	u8 quote_data[];
};

static int tdx_att_req(guid_t guid, u8 op_id, void *data, size_t data_len, u64 timeout)
{
	struct att_cmd_req_buf *req = req_buf;
	struct att_cmd_resp_buf *resp = resp_buf;
	u64 ret;

	if ((data_len + sizeof(*req)) >= SERVICE_REQ_BUF_LEN) {
		pr_info("Attestation cmd data len too large\n");
		return -EINVAL;
	}

	/* Initialize request service header */
	memcpy(req->hdr.guid, &guid, sizeof(guid_t));
	req->hdr.buf_len = sizeof(*req) + data_len;

	/* Initialize request command header */
	req->version = 0;
	req->cmd = TDX_ATT_CMD_REQ_SER;
	req->op = TDX_ATT_CMD_OP_COMM;

	/* Initialize request operation header */
	req->op_id = op_id;
	memcpy(req->op_data, data, data_len);

	ret = tdx_hcall_service(req_buf, resp_buf, 0, timeout);
	if (ret)
		return -EIO;

	if (resp->hdr.status) {
		pr_err("Service hypercall failed, err:%x\n", resp->hdr.status);
		return -EIO;
	}

	return 0;
}

int tdx_get_rpsrv_list(struct tsm_rpsrv *rpsrv, void *data)
{
	struct att_cmd_resp_buf *resp = resp_buf;
	struct att_cmd_op_query_req op_req = {};
	struct att_cmd_op_query_resp *op_resp;
	void *buf;
	int ret;

	op_req.version = TDX_ATT_OP_QUERY_VERSION;
	op_resp = (struct att_cmd_op_query_resp *)resp->op_data;

	ret = tdx_att_req(host_query_guid, TDX_ATT_OP_ID_QUERY_SERVICE,
			  &op_req, sizeof(op_req), 0);
	if (ret || op_resp->result)
		return -EIO;

	buf = kvmemdup(op_resp->guids, op_resp->result_size * sizeof(guid_t),
		       GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	rpsrv->rpsrv_count = op_resp->result_size;
	rpsrv->rpsrv_list = buf;

	return 0;
}

int tdx_get_att_key_id_list(struct tsm_rpsrv *rpsrv, void *data)
{
	struct att_cmd_resp_buf *resp = resp_buf;
	struct att_cmd_op_key_id_req op_req = {};
	struct att_cmd_op_key_id_resp *op_resp;
	void *buf;
	int ret;

	if (guid_is_null(&rpsrv->guid)) {
		pr_info("Fetching key IDs failed, invalid GUID\n");
		return -EINVAL;
	}

	op_resp = (struct att_cmd_op_key_id_resp *)resp->op_data;

	ret = tdx_att_req(rpsrv->guid, TDX_ATT_OP_ID_GET_KEY_ID,
			  &op_req, sizeof(op_req), 0);
	if (ret || op_resp->result)
		return -EIO;

	buf = kvmemdup(op_resp->guids, op_resp->result_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	rpsrv->att_key_id_count = op_resp->result_size;
	rpsrv->att_key_id_list = buf;

	return 0;
}

static int tdx_service_gen_quote(struct tsm_report *report, u8 *tdreport)
{
	struct att_cmd_resp_buf *resp = resp_buf;
	struct att_cmd_op_quote_req op_req = {};
	struct att_cmd_op_quote_resp *op_resp;
	int ret;
	u8 *buf;

	/* Initialize quote request operation header */
	op_req.version = TDX_ATT_OP_QUOTE_REQ_VERSION;
	op_req.report_size = TDX_REPORT_LEN;
	op_req.owner_data_size = 0;
	memcpy(op_req.att_key_id, &report->desc.attestation_key_guid, sizeof(guid_t));
	memcpy(op_req.data, tdreport, TDX_REPORT_LEN);

	op_resp = (struct att_cmd_op_quote_resp *)resp->op_data;

	ret = tdx_att_req(report->desc.remote_guid,
			  TDX_ATT_OP_ID_QUOTE_REQ,
			  &op_req, sizeof(op_req),
			  TDX_ATT_CMD_SERVICE_QUOTE_TIMEOUT);
	if (ret || op_resp->result) {
		pr_err("Quote Service hypercall failed, err:%x\n", op_resp->result);
		return -EIO;
	}

	buf = kvmemdup(op_resp->quote_data, op_resp->quote_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	report->outblob = buf;
	report->outblob_len = op_resp->quote_size;

	return 0;
}

static long tdx_get_report0(struct tdx_report_req __user *req)
{
	u8 *reportdata, *tdreport;
	long ret;

	reportdata = kmalloc(TDX_REPORTDATA_LEN, GFP_KERNEL);
	if (!reportdata)
		return -ENOMEM;

	tdreport = kzalloc(TDX_REPORT_LEN, GFP_KERNEL);
	if (!tdreport) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(reportdata, req->reportdata, TDX_REPORTDATA_LEN)) {
		ret = -EFAULT;
		goto out;
	}

	/* Generate TDREPORT0 using "TDG.MR.REPORT" TDCALL */
	ret = tdx_mcall_get_report0(reportdata, tdreport);
	if (ret)
		goto out;

	if (copy_to_user(req->tdreport, tdreport, TDX_REPORT_LEN))
		ret = -EFAULT;

out:
	kfree(reportdata);
	kfree(tdreport);

	return ret;
}

static void free_shared_pages(void *addr, size_t len)
{
	size_t aligned_len = PAGE_ALIGN(len);
	unsigned int count = aligned_len >> PAGE_SHIFT;

	if (set_memory_encrypted((unsigned long)addr, count)) {
		pr_err("Failed to restore encryption mask for Quote buffer, leak it\n");
		return;
	}

	free_pages_exact(addr, aligned_len);

}

static void *alloc_shared_pages(size_t len)
{
	size_t aligned_len = PAGE_ALIGN(len);
	unsigned int count = aligned_len >> PAGE_SHIFT;
	void *addr;

	addr = alloc_pages_exact(aligned_len, GFP_KERNEL | __GFP_ZERO);
	if (!addr)
		return NULL;

	if (set_memory_decrypted((unsigned long)addr, count)) {
		free_pages_exact(addr, aligned_len);
		return NULL;
	}

	return addr;
}

/*
 * wait_for_quote_completion() - Wait for Quote request completion
 * @quote_buf: Address of Quote buffer.
 * @timeout: Timeout in seconds to wait for the Quote generation.
 *
 * As per TDX GHCI v1.0 specification, sec titled "TDG.VP.VMCALL<GetQuote>",
 * the status field in the Quote buffer will be set to GET_QUOTE_IN_FLIGHT
 * while VMM processes the GetQuote request, and will change it to success
 * or error code after processing is complete. So wait till the status
 * changes from GET_QUOTE_IN_FLIGHT or the request being timed out.
 */
static int wait_for_quote_completion(struct tdx_quote_buf *quote_buf, u32 timeout)
{
	int i = 0;

	/*
	 * Quote requests usually take a few seconds to complete, so waking up
	 * once per second to recheck the status is fine for this use case.
	 */
	while (quote_buf->status == GET_QUOTE_IN_FLIGHT && i++ < timeout) {
		if (msleep_interruptible(MSEC_PER_SEC))
			return -EINTR;
	}

	return (i == timeout) ? -ETIMEDOUT : 0;
}

static int tdx_report_new(struct tsm_report *report, void *data)
{
	u8 *buf, *reportdata = NULL, *tdreport = NULL;
	struct tdx_quote_buf *quote_buf = quote_data;
	struct tsm_desc *desc = &report->desc;
	int ret;
	u64 err;

	/* TODO: switch to guard(mutex_intr) */
	if (mutex_lock_interruptible(&quote_lock))
		return -EINTR;

	/*
	 * If the previous request is timedout or interrupted, and the
	 * Quote buf status is still in GET_QUOTE_IN_FLIGHT (owned by
	 * VMM), don't permit any new request.
	 */
	if (quote_buf->status == GET_QUOTE_IN_FLIGHT) {
		ret = -EBUSY;
		goto done;
	}

	if (desc->inblob_len != TDX_REPORTDATA_LEN) {
		ret = -EINVAL;
		goto done;
	}

	reportdata = kmalloc(TDX_REPORTDATA_LEN, GFP_KERNEL);
	if (!reportdata) {
		ret = -ENOMEM;
		goto done;
	}

	tdreport = kzalloc(TDX_REPORT_LEN, GFP_KERNEL);
	if (!tdreport) {
		ret = -ENOMEM;
		goto done;
	}

	memcpy(reportdata, desc->inblob, desc->inblob_len);

	/* Generate TDREPORT0 using "TDG.MR.REPORT" TDCALL */
	ret = tdx_mcall_get_report0(reportdata, tdreport);
	if (ret) {
		pr_err("GetReport call failed\n");
		goto done;
	}

	if (!guid_is_null(&desc->remote_guid)) {
		ret = tdx_service_gen_quote(data, tdreport);
		goto done;
	}

	memset(quote_data, 0, GET_QUOTE_BUF_SIZE);

	/* Update Quote buffer header */
	quote_buf->version = GET_QUOTE_CMD_VER;
	quote_buf->in_len = TDX_REPORT_LEN;

	memcpy(quote_buf->data, tdreport, TDX_REPORT_LEN);

	err = tdx_hcall_get_quote(quote_data, GET_QUOTE_BUF_SIZE);
	if (err) {
		pr_err("GetQuote hypercall failed, status:%llx\n", err);
		ret = -EIO;
		goto done;
	}

	ret = wait_for_quote_completion(quote_buf, getquote_timeout);
	if (ret) {
		pr_err("GetQuote request timedout\n");
		goto done;
	}

	buf = kvmemdup(quote_buf->data, quote_buf->out_len, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto done;
	}

	report->outblob = buf;
	report->outblob_len = quote_buf->out_len;

	/*
	 * TODO: parse the PEM-formatted cert chain out of the quote buffer when
	 * provided
	 */
done:
	mutex_unlock(&quote_lock);
	kfree(reportdata);
	kfree(tdreport);

	return ret;
}

static long tdx_guest_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	switch (cmd) {
	case TDX_CMD_GET_REPORT0:
		return tdx_get_report0((struct tdx_report_req __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations tdx_guest_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tdx_guest_ioctl,
	.llseek = no_llseek,
};

static struct miscdevice tdx_misc_dev = {
	.name = KBUILD_MODNAME,
	.minor = MISC_DYNAMIC_MINOR,
	.fops = &tdx_guest_fops,
};

static const struct x86_cpu_id tdx_guest_ids[] = {
	X86_MATCH_FEATURE(X86_FEATURE_TDX_GUEST, NULL),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, tdx_guest_ids);

static const struct tsm_ops tdx_tsm_ops = {
	.name = KBUILD_MODNAME,
	.report_new = tdx_report_new,
	.get_rpsrv_list = tdx_get_rpsrv_list,
	.get_att_key_id_list = tdx_get_att_key_id_list,
};

static int tdx_service_init(void)
{
	req_buf = alloc_shared_pages(SERVICE_REQ_BUF_LEN);
	if (!req_buf)
		return -ENOMEM;

	resp_buf = alloc_shared_pages(SERVICE_RESP_BUF_LEN);
	if (!resp_buf) {
		free_shared_pages(req_buf, SERVICE_REQ_BUF_LEN);
		return -ENOMEM;
	}

	return 0;

}

static void tdx_service_deinit(void)
{
	if (req_buf)
		free_shared_pages(req_buf, SERVICE_REQ_BUF_LEN);
	if (resp_buf)
		free_shared_pages(req_buf, SERVICE_RESP_BUF_LEN);
}

static int __init tdx_guest_init(void)
{
	int ret;

	if (!x86_match_cpu(tdx_guest_ids))
		return -ENODEV;

	ret = misc_register(&tdx_misc_dev);
	if (ret)
		return ret;

	quote_data = alloc_shared_pages(GET_QUOTE_BUF_SIZE);
	if (!quote_data) {
		pr_err("Failed to allocate Quote buffer\n");
		ret = -ENOMEM;
		goto free_misc;
	}

	ret = tdx_service_init();
	if (ret) {
		pr_err("Failed to allocate service buffers\n");
		ret = -ENOMEM;
		goto free_quote;
	}

	ret = tsm_register(&tdx_tsm_ops, NULL, NULL);
	if (ret)
		goto free_service;

	return 0;

free_service:
	tdx_service_deinit();
free_quote:
	free_shared_pages(quote_data, GET_QUOTE_BUF_SIZE);
free_misc:
	misc_deregister(&tdx_misc_dev);

	return ret;
}
module_init(tdx_guest_init);

static void __exit tdx_guest_exit(void)
{
	tsm_unregister(&tdx_tsm_ops);
	free_shared_pages(quote_data, GET_QUOTE_BUF_SIZE);
	tdx_service_deinit();
	misc_deregister(&tdx_misc_dev);
}
module_exit(tdx_guest_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX Guest Driver");
MODULE_LICENSE("GPL");
