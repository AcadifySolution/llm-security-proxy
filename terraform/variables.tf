# MIT License
# Copyright (c) 2026 Acadify Solutions

variable "aws_region" {
  type        = string
  description = "The target AWS Region for deployment."
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Application deployment tier (e.g. dev, staging, prod)."
  default     = "prod"
}

variable "ecr_image_uri" {
  type        = string
  description = "The ECR Registry URI containing the docker container of the LLM security proxy"
  default     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/acadify/llm-security-proxy"
}
