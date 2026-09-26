package graph

import (
	"testing"

	"github.com/ghostroute/ghostroute/pkg/model"
)

func TestDAGConstruction(t *testing.T) {
	resources := []*model.Resource{
		{
			Address: "aws_instance.app",
			Type:    "aws_instance",
			Name:    "app",
			Attributes: map[string]interface{}{
				"id": "i-0987654321",
			},
		},
		{
			Address: "aws_ebs_volume.vol",
			Type:    "aws_ebs_volume",
			Name:    "vol",
			Attributes: map[string]interface{}{
				"id":   "vol-1234567890",
				"size": 50,
			},
		},
		{
			Address: "aws_volume_attachment.att",
			Type:    "aws_volume_attachment",
			Name:    "att",
			Attributes: map[string]interface{}{
				"instance_id": "i-0987654321",
				"volume_id":   "vol-1234567890",
			},
			Dependencies: []string{"aws_instance.app", "aws_ebs_volume.vol"},
		},
	}

	dag := BuildDAG(resources)

	if len(dag.Nodes) != 3 {
		t.Fatalf("Expected 3 nodes in DAG, got %d", len(dag.Nodes))
	}

	volNode := dag.Nodes["aws_ebs_volume.vol"]
	if volNode == nil {
		t.Fatal("Expected node for aws_ebs_volume.vol")
	}

	// Volume should have incoming edge from aws_volume_attachment.att
	if dag.InDegree("aws_ebs_volume.vol") == 0 {
		t.Errorf("Expected in-degree > 0 for attached volume, got %d", dag.InDegree("aws_ebs_volume.vol"))
	}

	instNode := dag.Nodes["aws_instance.app"]
	if instNode == nil {
		t.Fatal("Expected node for aws_instance.app")
	}
	if dag.InDegree("aws_instance.app") == 0 {
		t.Errorf("Expected in-degree > 0 for instance, got %d", dag.InDegree("aws_instance.app"))
	}
}
