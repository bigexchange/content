

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* BigId
* AWS - S3

### Scripts

* DeleteContext
* Set
* MergeS3BucketPolicy

### Commands

* get-objects-from-catalog
* aws-s3-get-bucket-policy
* aws-s3-put-bucket-policy

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| bucket | The bucket policy will be applied to. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![S3 Multiple File Remediation](../doc_files/S3_Multiple_File_Remediation.png)
