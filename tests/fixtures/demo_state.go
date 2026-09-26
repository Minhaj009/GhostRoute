package fixtures

// VulnerableAWSStateJSON is an embedded production-grade Terraform state with unattached zombies & dangling DNS.
const VulnerableAWSStateJSON = `{
  "version": 4,
  "terraform_version": "1.7.0",
  "serial": 45,
  "lineage": "f62b8813-8a39-44be-8704-58a36d2bf260",
  "outputs": {},
  "resources": [
    {
      "mode": "managed",
      "type": "aws_instance",
      "name": "web_server",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 1,
          "attributes": {
            "id": "i-0123456789abcdef0",
            "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
            "instance_type": "t3.medium"
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_ebs_volume",
      "name": "web_data_disk",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 0,
          "attributes": {
            "id": "vol-0123456789abcdef1",
            "size": 100,
            "type": "gp3"
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_volume_attachment",
      "name": "web_data_att",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 0,
          "attributes": {
            "instance_id": "i-0123456789abcdef0",
            "volume_id": "vol-0123456789abcdef1"
          },
          "dependencies": [
            "aws_instance.web_server",
            "aws_ebs_volume.web_data_disk"
          ]
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_ebs_volume",
      "name": "abandoned_backup_vol",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 0,
          "attributes": {
            "id": "vol-9999888877776666a",
            "size": 250,
            "type": "gp2"
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_eip",
      "name": "unattached_static_ip",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 0,
          "attributes": {
            "id": "eipalloc-01122334455667788",
            "allocation_id": "eipalloc-01122334455667788",
            "public_ip": "54.210.120.30",
            "instance": "",
            "network_interface": ""
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_lb",
      "name": "orphaned_alb",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 0,
          "attributes": {
            "arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/orphaned-alb/50dc6c495c0c9188",
            "name": "orphaned-alb"
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_nat_gateway",
      "name": "idle_nat_gw",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 0,
          "attributes": {
            "id": "nat-08899aabbccddeeff"
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_route53_record",
      "name": "dangling_s3_cname",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 2,
          "attributes": {
            "name": "assets.production-corp.com",
            "type": "CNAME",
            "records": [
              "abandoned-corp-assets-2023.s3.amazonaws.com"
            ]
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_route53_record",
      "name": "dangling_github_pages",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 2,
          "attributes": {
            "name": "docs.production-corp.com",
            "type": "CNAME",
            "records": [
              "old-project-docs.github.io"
            ]
          }
        }
      ]
    }
  ]
}
`

// CleanAWSStateJSON models a properly secured and fully attached infrastructure.
const CleanAWSStateJSON = `{
  "version": 4,
  "terraform_version": "1.7.0",
  "serial": 10,
  "lineage": "c84f8842-8941-4560-a2b1-6a2d1d0c4eb5",
  "resources": [
    {
      "mode": "managed",
      "type": "aws_instance",
      "name": "active_web",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "attributes": {
            "id": "i-0987654321fedcba0"
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "aws_eip",
      "name": "web_ip",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "attributes": {
            "id": "eipalloc-99887766",
            "instance": "i-0987654321fedcba0",
            "public_ip": "54.10.20.30"
          }
        }
      ]
    }
  ]
}
`
