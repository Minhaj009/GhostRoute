package graph

import (
	"fmt"
	"strings"

	"github.com/ghostroute/ghostroute/pkg/model"
)

// OrphanDetector scans the resource DAG for zombie / unattached cloud assets.
type OrphanDetector struct {
	dag *DAG
}

// NewOrphanDetector initializes an OrphanDetector with the provided DAG.
func NewOrphanDetector(dag *DAG) *OrphanDetector {
	return &OrphanDetector{dag: dag}
}

// DetectOrphans identifies all zombie and unattached cloud resources in the DAG.
func (od *OrphanDetector) DetectOrphans() []model.Finding {
	var findings []model.Finding

	for _, node := range od.dag.Nodes {
		res := node.Resource

		switch res.Type {
		// AWS Elastic IP
		case "aws_eip":
			if od.isAWSUnattachedEIP(node) {
				findings = append(findings, model.Finding{
					ID:                 "GHOST-001",
					RuleID:             "aws-unattached-eip",
					Title:              "Unattached Elastic IP Address",
					Category:           model.CategoryZombie,
					Severity:           model.SeverityHigh,
					ResourceAddress:    res.Address,
					ResourceType:       res.Type,
					CloudProvider:      "aws",
					Description:        fmt.Sprintf("Elastic IP '%s' is not associated with any active EC2 instance or network interface.", res.Address),
					Impact:             "AWS charges $0.005/hour ($3.65/month) for each unattached or idle IPv4 address.",
					RemediationCommand: fmt.Sprintf("terraform state rm %s", res.Address),
					RemediationHCL:     fmt.Sprintf("# Remove or associate resource \"%s\" \"%s\"", res.Type, res.Name),
				})
			}

		// AWS EBS Volume
		case "aws_ebs_volume":
			if od.isAWSDetachedEBS(node) {
				sizeGB := res.GetIntAttr("size")
				if sizeGB == 0 {
					sizeGB = 50 // default assumption if unspecified
				}
				volType := res.GetStringAttr("type")
				if volType == "" {
					volType = "gp3"
				}
				findings = append(findings, model.Finding{
					ID:                 "GHOST-002",
					RuleID:             "aws-detached-ebs-volume",
					Title:              "Detached EBS Storage Volume",
					Category:           model.CategoryZombie,
					Severity:           model.SeverityMedium,
					ResourceAddress:    res.Address,
					ResourceType:       res.Type,
					CloudProvider:      "aws",
					Description:        fmt.Sprintf("EBS volume '%s' (%d GB, %s) is unattached with 0 incoming instance references.", res.Address, sizeGB, volType),
					Impact:             fmt.Sprintf("AWS charges storage fees indefinitely for detached %s volumes ($0.08 - $0.125/GB/month).", volType),
					RemediationCommand: fmt.Sprintf("terraform state rm %s", res.Address),
					RemediationHCL:     fmt.Sprintf("# Snapshot or remove resource \"%s\" \"%s\"", res.Type, res.Name),
				})
			}

		// AWS Application / Network Load Balancer
		case "aws_lb", "aws_alb":
			if od.isAWSOrphanedLB(node) {
				findings = append(findings, model.Finding{
					ID:                 "GHOST-003",
					RuleID:             "aws-orphaned-load-balancer",
					Title:              "Orphaned Load Balancer Without Active Listeners",
					Category:           model.CategoryZombie,
					Severity:           model.SeverityHigh,
					ResourceAddress:    res.Address,
					ResourceType:       res.Type,
					CloudProvider:      "aws",
					Description:        fmt.Sprintf("Load Balancer '%s' has 0 active listeners configured in state.", res.Address),
					Impact:             "AWS charges ~$16.43/month base fee plus LCU charges for idle load balancers.",
					RemediationCommand: fmt.Sprintf("terraform state rm %s", res.Address),
					RemediationHCL:     fmt.Sprintf("# Remove unused load balancer \"%s\" \"%s\"", res.Type, res.Name),
				})
			}

		// AWS LB Target Group
		case "aws_lb_target_group", "aws_alb_target_group":
			if od.isAWSOrphanedTargetGroup(node) {
				findings = append(findings, model.Finding{
					ID:                 "GHOST-004",
					RuleID:             "aws-orphaned-target-group",
					Title:              "Target Group Without Target Instances",
					Category:           model.CategoryZombie,
					Severity:           model.SeverityMedium,
					ResourceAddress:    res.Address,
					ResourceType:       res.Type,
					CloudProvider:      "aws",
					Description:        fmt.Sprintf("Target Group '%s' has no target attachments or listener routing configured.", res.Address),
					Impact:             "Accumulates stale configuration and security surface without serving traffic.",
					RemediationCommand: fmt.Sprintf("terraform state rm %s", res.Address),
					RemediationHCL:     fmt.Sprintf("# Remove unused target group \"%s\" \"%s\"", res.Type, res.Name),
				})
			}

		// AWS NAT Gateway
		case "aws_nat_gateway":
			if od.isAWSUnroutedNATGateway(node) {
				findings = append(findings, model.Finding{
					ID:                 "GHOST-005",
					RuleID:             "aws-unrouted-nat-gateway",
					Title:              "Unrouted / Idle NAT Gateway",
					Category:           model.CategoryZombie,
					Severity:           model.SeverityHigh,
					ResourceAddress:    res.Address,
					ResourceType:       res.Type,
					CloudProvider:      "aws",
					Description:        fmt.Sprintf("NAT Gateway '%s' has 0 routing table references directing subnet traffic to it.", res.Address),
					Impact:             "AWS charges $0.045/hour ($32.85/month) baseline for each running NAT Gateway.",
					RemediationCommand: fmt.Sprintf("terraform state rm %s", res.Address),
					RemediationHCL:     fmt.Sprintf("# Remove unrouted NAT gateway \"%s\" \"%s\"", res.Type, res.Name),
				})
			}

		// AWS Unattached Network Interface (ENI)
		case "aws_network_interface":
			if od.isAWSUnattachedENI(node) {
				findings = append(findings, model.Finding{
					ID:                 "GHOST-006",
					RuleID:             "aws-unattached-network-interface",
					Title:              "Unattached Elastic Network Interface (ENI)",
					Category:           model.CategoryZombie,
					Severity:           model.SeverityLow,
					ResourceAddress:    res.Address,
					ResourceType:       res.Type,
					CloudProvider:      "aws",
					Description:        fmt.Sprintf("Network Interface '%s' is not attached to any EC2 instance or service.", res.Address),
					Impact:             "Consumes VPC private IP addresses and potential subnet IP allocation limits.",
					RemediationCommand: fmt.Sprintf("terraform state rm %s", res.Address),
					RemediationHCL:     fmt.Sprintf("# Remove unattached interface \"%s\" \"%s\"", res.Type, res.Name),
				})
			}

		// GCP Static External IP
		case "google_compute_address":
			if od.isGCPUnusedAddress(node) {
				findings = append(findings, model.Finding{
					ID:                 "GHOST-007",
					RuleID:             "gcp-unused-external-ip",
					Title:              "Unused GCP Static External IP Address",
					Category:           model.CategoryZombie,
					Severity:           model.SeverityHigh,
					ResourceAddress:    res.Address,
					ResourceType:       res.Type,
					CloudProvider:      "gcp",
					Description:        fmt.Sprintf("GCP Static IP '%s' is reserved but not in use by any VM or forwarding rule.", res.Address),
					Impact:             "Google Cloud charges $0.010/hour ($7.30/month) for unused static external IP addresses.",
					RemediationCommand: fmt.Sprintf("terraform state rm %s", res.Address),
					RemediationHCL:     fmt.Sprintf("# Release unused address \"%s\" \"%s\"", res.Type, res.Name),
				})
			}

		// GCP Persistent Disk
		case "google_compute_disk":
			if od.isGCPDetachedDisk(node) {
				sizeGB := res.GetIntAttr("size")
				if sizeGB == 0 {
					sizeGB = 50
				}
				findings = append(findings, model.Finding{
					ID:                 "GHOST-008",
					RuleID:             "gcp-detached-persistent-disk",
					Title:              "Detached GCP Persistent Disk",
					Category:           model.CategoryZombie,
					Severity:           model.SeverityMedium,
					ResourceAddress:    res.Address,
					ResourceType:       res.Type,
					CloudProvider:      "gcp",
					Description:        fmt.Sprintf("GCP Persistent Disk '%s' (%d GB) is not attached to any compute instance.", res.Address, sizeGB),
					Impact:             "Google Cloud charges persistent disk storage rates regardless of attachment status.",
					RemediationCommand: fmt.Sprintf("terraform state rm %s", res.Address),
					RemediationHCL:     fmt.Sprintf("# Snapshot and delete \"%s\" \"%s\"", res.Type, res.Name),
				})
			}

		// Azure Public IP
		case "azurerm_public_ip":
			if od.isAzureUnattachedPublicIP(node) {
				findings = append(findings, model.Finding{
					ID:                 "GHOST-009",
					RuleID:             "azure-unattached-public-ip",
					Title:              "Unattached Azure Public IP Address",
					Category:           model.CategoryZombie,
					Severity:           model.SeverityHigh,
					ResourceAddress:    res.Address,
					ResourceType:       res.Type,
					CloudProvider:      "azure",
					Description:        fmt.Sprintf("Azure Public IP '%s' is not associated with any NIC, Bastion, or Load Balancer.", res.Address),
					Impact:             "Azure charges standard hourly rates for unassociated public IP addresses ($3.65/month).",
					RemediationCommand: fmt.Sprintf("terraform state rm %s", res.Address),
					RemediationHCL:     fmt.Sprintf("# Delete unused IP \"%s\" \"%s\"", res.Type, res.Name),
				})
			}

		// Azure Managed Disk
		case "azurerm_managed_disk":
			if od.isAzureDetachedManagedDisk(node) {
				sizeGB := res.GetIntAttr("disk_size_gb")
				if sizeGB == 0 {
					sizeGB = 32
				}
				findings = append(findings, model.Finding{
					ID:                 "GHOST-010",
					RuleID:             "azure-detached-managed-disk",
					Title:              "Detached Azure Managed Disk",
					Category:           model.CategoryZombie,
					Severity:           model.SeverityMedium,
					ResourceAddress:    res.Address,
					ResourceType:       res.Type,
					CloudProvider:      "azure",
					Description:        fmt.Sprintf("Azure Managed Disk '%s' (%d GB) is not attached to any virtual machine.", res.Address, sizeGB),
					Impact:             "Azure bills managed disk provisioned size continuously whether attached or detached.",
					RemediationCommand: fmt.Sprintf("terraform state rm %s", res.Address),
					RemediationHCL:     fmt.Sprintf("# Snapshot and remove \"%s\" \"%s\"", res.Type, res.Name),
				})
			}
		}
	}

	return findings
}

// isAWSUnattachedEIP checks if an aws_eip is not attached to an instance, ENI, or association
func (od *OrphanDetector) isAWSUnattachedEIP(node *Node) bool {
	res := node.Resource
	inst := res.GetStringAttr("instance")
	eni := res.GetStringAttr("network_interface")
	if inst != "" || eni != "" {
		return false
	}

	// Check if any aws_eip_association or aws_nat_gateway references this node
	for _, inc := range node.Incoming {
		if inc.Resource.Type == "aws_eip_association" || inc.Resource.Type == "aws_nat_gateway" {
			return false
		}
	}

	for _, out := range node.Outgoing {
		if out.Resource.Type == "aws_instance" || out.Resource.Type == "aws_network_interface" {
			return false
		}
	}

	return true
}

// isAWSDetachedEBS checks if an aws_ebs_volume has no attachments or instance associations
func (od *OrphanDetector) isAWSDetachedEBS(node *Node) bool {
	// If incoming edges has an aws_volume_attachment or aws_instance, it is attached
	for _, inc := range node.Incoming {
		if inc.Resource.Type == "aws_volume_attachment" || inc.Resource.Type == "aws_instance" {
			return false
		}
	}
	for _, out := range node.Outgoing {
		if out.Resource.Type == "aws_instance" {
			return false
		}
	}
	return true
}

// isAWSOrphanedLB checks if an ALB/NLB has 0 listeners
func (od *OrphanDetector) isAWSOrphanedLB(node *Node) bool {
	for _, inc := range node.Incoming {
		if inc.Resource.Type == "aws_lb_listener" || inc.Resource.Type == "aws_alb_listener" {
			return false
		}
	}
	for _, out := range node.Outgoing {
		if out.Resource.Type == "aws_lb_listener" || out.Resource.Type == "aws_alb_listener" {
			return false
		}
	}
	return true
}

// isAWSOrphanedTargetGroup checks if target group has 0 targets attached
func (od *OrphanDetector) isAWSOrphanedTargetGroup(node *Node) bool {
	hasListener := false
	hasAttachment := false

	for _, inc := range node.Incoming {
		if strings.Contains(inc.Resource.Type, "listener") {
			hasListener = true
		}
		if strings.Contains(inc.Resource.Type, "target_group_attachment") {
			hasAttachment = true
		}
	}
	for _, out := range node.Outgoing {
		if strings.Contains(out.Resource.Type, "listener") {
			hasListener = true
		}
		if strings.Contains(out.Resource.Type, "target_group_attachment") {
			hasAttachment = true
		}
	}

	// Orphaned if either no listener routes to it OR has 0 targets
	return !hasListener || !hasAttachment
}

// isAWSUnroutedNATGateway checks if any route directs traffic to this NAT gateway
func (od *OrphanDetector) isAWSUnroutedNATGateway(node *Node) bool {
	for _, inc := range node.Incoming {
		if inc.Resource.Type == "aws_route" {
			return false
		}
	}
	return true
}

// isAWSUnattachedENI checks if an ENI has empty attachment
func (od *OrphanDetector) isAWSUnattachedENI(node *Node) bool {
	for _, inc := range node.Incoming {
		if inc.Resource.Type == "aws_instance" || inc.Resource.Type == "aws_network_interface_attachment" {
			return false
		}
	}
	for _, out := range node.Outgoing {
		if out.Resource.Type == "aws_instance" {
			return false
		}
	}
	return true
}

// isGCPUnusedAddress checks if google_compute_address is not used
func (od *OrphanDetector) isGCPUnusedAddress(node *Node) bool {
	for _, inc := range node.Incoming {
		if strings.Contains(inc.Resource.Type, "instance") || strings.Contains(inc.Resource.Type, "forwarding_rule") {
			return false
		}
	}
	return true
}

// isGCPDetachedDisk checks if google_compute_disk is unattached
func (od *OrphanDetector) isGCPDetachedDisk(node *Node) bool {
	for _, inc := range node.Incoming {
		if inc.Resource.Type == "google_compute_attached_disk" || inc.Resource.Type == "google_compute_instance" {
			return false
		}
	}
	return true
}

// isAzureUnattachedPublicIP checks if azurerm_public_ip is unassociated
func (od *OrphanDetector) isAzureUnattachedPublicIP(node *Node) bool {
	for _, inc := range node.Incoming {
		if strings.Contains(inc.Resource.Type, "network_interface") || strings.Contains(inc.Resource.Type, "lb") {
			return false
		}
	}
	return true
}

// isAzureDetachedManagedDisk checks if azurerm_managed_disk is detached
func (od *OrphanDetector) isAzureDetachedManagedDisk(node *Node) bool {
	for _, inc := range node.Incoming {
		if inc.Resource.Type == "azurerm_virtual_machine_data_disk_attachment" || strings.Contains(inc.Resource.Type, "virtual_machine") {
			return false
		}
	}
	return true
}
