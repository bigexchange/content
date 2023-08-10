Given the full object name of an object in bigid, determine the name of the data source it belongs to. Then scan it if it has not been scanned within the last 7 days.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* BigId

### Scripts

* IsGreaterThan
* GetTime

### Commands

* closeInvestigation
* get-objects-from-catalog
* get-ds-connections
* run-ds-scan

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| fullyQualifiedName |  |  | The fully qualified name of an object whose datasource you want to scan. |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Update Scan Playbook](../doc_files/Update_Scan_Playbook.png)
