# Intentionally misconfigured Terraform for the IaC scan. Never apply this.
# Nothing here is deployed by the pipeline; Trivy only reads the files.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Public, unencrypted, unversioned bucket with no public-access block
resource "aws_s3_bucket" "uploads" {
  bucket = "appsec-demo-uploads"
}

resource "aws_s3_bucket_acl" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  acl    = "public-read"
}

# SSH open to the whole internet, unrestricted egress
resource "aws_security_group" "web" {
  name        = "appsec-demo-web"
  description = "demo"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IMDSv1 allowed, unencrypted root volume, public IP
resource "aws_instance" "web" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.web.id]

  metadata_options {
    http_tokens = "optional"
  }

  root_block_device {
    encrypted = false
  }
}
