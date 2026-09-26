package graph

import (
	"strings"

	"github.com/ghostroute/ghostroute/pkg/model"
)

// Node represents a vertex in the cloud resource dependency graph.
type Node struct {
	Resource *model.Resource
	Incoming map[string]*Node // Resources that point to or attach to this resource
	Outgoing map[string]*Node // Resources that this resource points to or depends on
}

// DAG represents the Directed Acyclic Graph of all cloud resources.
type DAG struct {
	Nodes    map[string]*Node            // Keyed by resource address (e.g., aws_ebs_volume.vol1)
	byID     map[string]*model.Resource  // Keyed by resource ID or ARN for O(1) attribute matching
	byIP     map[string]*model.Resource  // Keyed by IP address for EIP matching
}

// NewDAG initializes an empty DAG.
func NewDAG() *DAG {
	return &DAG{
		Nodes: make(map[string]*Node),
		byID:  make(map[string]*model.Resource),
		byIP:  make(map[string]*model.Resource),
	}
}

// BuildDAG constructs the resource dependency DAG from a slice of parsed resources.
func BuildDAG(resources []*model.Resource) *DAG {
	dag := NewDAG()

	// Pass 1: Register all nodes and build lookup indexes
	for _, res := range resources {
		node := &Node{
			Resource: res,
			Incoming: make(map[string]*Node),
			Outgoing: make(map[string]*Node),
		}
		dag.Nodes[res.Address] = node

		// Index by ID if present
		if id := res.GetStringAttr("id"); id != "" {
			dag.byID[id] = res
		}
		// Index by ARN if present
		if arn := res.GetStringAttr("arn"); arn != "" {
			dag.byID[arn] = res
		}
		// Index by Allocation ID if present (EIP)
		if allocID := res.GetStringAttr("allocation_id"); allocID != "" {
			dag.byID[allocID] = res
		}
		// Index by Public IP if present
		if pubIP := res.GetStringAttr("public_ip"); pubIP != "" {
			dag.byIP[pubIP] = res
		}
	}

	// Pass 2: Connect explicit dependencies
	for _, node := range dag.Nodes {
		for _, depAddr := range node.Resource.Dependencies {
			// DepAddr might be bare address or have module prefixes
			targetNode := dag.findNodeByFuzzyAddress(depAddr)
			if targetNode != nil && targetNode != node {
				dag.addEdge(node, targetNode)
			}
		}
	}

	// Pass 3: Connect implicit attribute relationships
	dag.connectAttributeRelationships()

	return dag
}

// addEdge connects from -> to (from depends on to; to has incoming link from from)
func (dag *DAG) addEdge(from, to *Node) {
	from.Outgoing[to.Resource.Address] = to
	to.Incoming[from.Resource.Address] = from
}

// findNodeByFuzzyAddress attempts to locate a node by exact address or suffix matching
func (dag *DAG) findNodeByFuzzyAddress(addr string) *Node {
	if node, ok := dag.Nodes[addr]; ok {
		return node
	}
	// Try without array brackets or with matching suffix
	cleanAddr := strings.Split(addr, "[")[0]
	if node, ok := dag.Nodes[cleanAddr]; ok {
		return node
	}
	for nodeAddr, node := range dag.Nodes {
		if strings.HasSuffix(nodeAddr, "."+addr) || strings.HasSuffix(addr, "."+nodeAddr) {
			return node
		}
	}
	return nil
}

// connectAttributeRelationships inspects specific resource attachment patterns
func (dag *DAG) connectAttributeRelationships() {
	for _, node := range dag.Nodes {
		res := node.Resource

		switch res.Type {
		// AWS EBS volume attachment
		case "aws_volume_attachment":
			volID := res.GetStringAttr("volume_id")
			instID := res.GetStringAttr("instance_id")
			if volRes, ok := dag.byID[volID]; ok {
				if volNode, ok := dag.Nodes[volRes.Address]; ok {
					dag.addEdge(node, volNode)
				}
			}
			if instRes, ok := dag.byID[instID]; ok {
				if instNode, ok := dag.Nodes[instRes.Address]; ok {
					dag.addEdge(node, instNode)
				}
			}

		// AWS EIP association
		case "aws_eip_association":
			allocID := res.GetStringAttr("allocation_id")
			instID := res.GetStringAttr("instance_id")
			eniID := res.GetStringAttr("network_interface_id")

			if eipRes, ok := dag.byID[allocID]; ok {
				if eipNode, ok := dag.Nodes[eipRes.Address]; ok {
					dag.addEdge(node, eipNode)
				}
			}
			if instID != "" {
				if instRes, ok := dag.byID[instID]; ok {
					if instNode, ok := dag.Nodes[instRes.Address]; ok {
						dag.addEdge(node, instNode)
					}
				}
			}
			if eniID != "" {
				if eniRes, ok := dag.byID[eniID]; ok {
					if eniNode, ok := dag.Nodes[eniRes.Address]; ok {
						dag.addEdge(node, eniNode)
					}
				}
			}

		// AWS Elastic IP direct instance or network interface attribute
		case "aws_eip":
			instID := res.GetStringAttr("instance")
			eniID := res.GetStringAttr("network_interface")
			if instID != "" {
				if instRes, ok := dag.byID[instID]; ok {
					if instNode, ok := dag.Nodes[instRes.Address]; ok {
						dag.addEdge(node, instNode)
					}
				}
			}
			if eniID != "" {
				if eniRes, ok := dag.byID[eniID]; ok {
					if eniNode, ok := dag.Nodes[eniRes.Address]; ok {
						dag.addEdge(node, eniNode)
					}
				}
			}

		// AWS LB Listener -> Target Group & ALB
		case "aws_lb_listener", "aws_alb_listener":
			lbARN := res.GetStringAttr("load_balancer_arn")
			if lbRes, ok := dag.byID[lbARN]; ok {
				if lbNode, ok := dag.Nodes[lbRes.Address]; ok {
					dag.addEdge(node, lbNode)
				}
			}
			// Search default_action for target_group_arn
			for k, v := range res.Attributes {
				if strings.Contains(k, "target_group_arn") {
					if tgARN, ok := v.(string); ok && tgARN != "" {
						if tgRes, ok := dag.byID[tgARN]; ok {
							if tgNode, ok := dag.Nodes[tgRes.Address]; ok {
								dag.addEdge(node, tgNode)
							}
						}
					}
				}
			}

		// AWS LB Target Group Attachment
		case "aws_lb_target_group_attachment", "aws_alb_target_group_attachment":
			tgARN := res.GetStringAttr("target_group_arn")
			targetID := res.GetStringAttr("target_id")
			if tgRes, ok := dag.byID[tgARN]; ok {
				if tgNode, ok := dag.Nodes[tgRes.Address]; ok {
					dag.addEdge(node, tgNode)
				}
			}
			if targetID != "" {
				if targetRes, ok := dag.byID[targetID]; ok {
					if targetNode, ok := dag.Nodes[targetRes.Address]; ok {
						dag.addEdge(node, targetNode)
					}
				}
			}

		// AWS Route -> NAT Gateway
		case "aws_route":
			natID := res.GetStringAttr("nat_gateway_id")
			rtID := res.GetStringAttr("route_table_id")
			if natRes, ok := dag.byID[natID]; ok {
				if natNode, ok := dag.Nodes[natRes.Address]; ok {
					dag.addEdge(node, natNode)
				}
			}
			if rtRes, ok := dag.byID[rtID]; ok {
				if rtNode, ok := dag.Nodes[rtRes.Address]; ok {
					dag.addEdge(node, rtNode)
				}
			}

		// Azure Virtual Machine Data Disk Attachment
		case "azurerm_virtual_machine_data_disk_attachment":
			diskID := res.GetStringAttr("managed_disk_id")
			vmID := res.GetStringAttr("virtual_machine_id")
			if diskRes, ok := dag.byID[diskID]; ok {
				if diskNode, ok := dag.Nodes[diskRes.Address]; ok {
					dag.addEdge(node, diskNode)
				}
			}
			if vmRes, ok := dag.byID[vmID]; ok {
				if vmNode, ok := dag.Nodes[vmRes.Address]; ok {
					dag.addEdge(node, vmNode)
				}
			}
		}
	}
}

// InDegree returns the number of incoming references to the resource.
func (dag *DAG) InDegree(address string) int {
	if node, ok := dag.Nodes[address]; ok {
		return len(node.Incoming)
	}
	return 0
}

// OutDegree returns the number of outgoing dependencies from the resource.
func (dag *DAG) OutDegree(address string) int {
	if node, ok := dag.Nodes[address]; ok {
		return len(node.Outgoing)
	}
	return 0
}

// GetIncoming returns all nodes referencing this address.
func (dag *DAG) GetIncoming(address string) []*Node {
	if node, ok := dag.Nodes[address]; ok {
		res := make([]*Node, 0, len(node.Incoming))
		for _, inc := range node.Incoming {
			res = append(res, inc)
		}
		return res
	}
	return nil
}

// GetOutgoing returns all nodes referenced by this address.
func (dag *DAG) GetOutgoing(address string) []*Node {
	if node, ok := dag.Nodes[address]; ok {
		res := make([]*Node, 0, len(node.Outgoing))
		for _, out := range node.Outgoing {
			res = append(res, out)
		}
		return res
	}
	return nil
}
