# MIT License
# Copyright (c) 2026 Acadify Solutions

output "proxy_alb_dns_name" {
  value       = aws_lb.alb.dns_name
  description = "The public facing load balancer endpoint to route OpenAI client requests to."
}

output "ecs_cluster_name" {
  value       = aws_ecs_cluster.cluster.name
  description = "The name of the created ECS Fargate cluster."
}

output "kms_key_arn" {
  value       = aws_kms_key.log_key.arn
  description = "The KMS key ARN used to secure audit trails and environment secrets."
}
