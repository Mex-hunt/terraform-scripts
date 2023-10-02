
terraform {

  # Intentionally empty. Will be filled by Terragrunt.

  backend "s3" {}

  required_version = "1.3.3"

  required_providers {

    aws = "~> 3.0"

  }

}



provider "aws" {

  region = var.region

  assume_role {

    role_arn     = "arn:aws:iam::${var.account}:role/InfrastructureBuildRole"

    session_name = "INFRASTRUCTURE_BUILD"

  }

}



resource "aws_elasticache_subnet_group" "subnet_group" {

  name       = format("%s-subnet-group", lookup(var.elasticache_redis, "cluster_id"))

  subnet_ids = var.subnet_ids

}



#Single-node redis instance(cluster mode disabled)

resource "aws_elasticache_cluster" "elasticache_cluster" {

  count                        = lookup(var.elasticache_redis, "enable_single_node_redis", var.elasticache_redis_default["enable_single_node_redis"]) ? 1 : 0

  cluster_id                   = lookup(var.elasticache_redis, "cluster_id")

  engine                       = lookup(var.elasticache_redis, "engine", var.elasticache_redis_default["engine"])

  node_type                    = lookup(var.elasticache_redis, "node_type", var.elasticache_redis_default["node_type"])

  num_cache_nodes              = lookup(var.elasticache_redis, "num_cache_nodes", var.elasticache_redis_default["num_cache_nodes"])

  parameter_group_name         = lookup(var.elasticache_redis, "parameter_group_name", var.elasticache_redis_default["parameter_group_name"])

  engine_version               = lookup(var.elasticache_redis, "engine_version", var.elasticache_redis_default["engine_version"])

  port                         = lookup(var.elasticache_redis, "port", var.elasticache_redis_default["port"])

  preferred_availability_zones = var.preferred_cache_cluster_azs

  az_mode                      = lookup(var.elasticache_redis, "az_mode", var.elasticache_redis_default["az_mode"])

  subnet_group_name            = aws_elasticache_subnet_group.subnet_group.name

  snapshot_name                = lookup(var.elasticache_redis, "snapshot_name ", null)

  snapshot_window              = lookup(var.elasticache_redis, "snapshot_window ", var.elasticache_redis_default["snapshot_window"])

  snapshot_retention_limit     = lookup(var.elasticache_redis, "snapshot_retention_limit", var.elasticache_redis_default["snapshot_retention_limit"])

  security_group_ids           = var.security_group_ids

  notification_topic_arn       = var.notification_topic_arn != "" ? var.notification_topic_arn : null

  network_type                 = lookup(var.elasticache_redis, "network_type", var.elasticache_redis_default["network_type"])

  maintenance_window           = lookup(var.elasticache_redis, "maintenance_window", var.elasticache_redis_default["maintenance_window"])

  dynamic "log_delivery_configuration" {

    for_each = var.log_delivery_configuration != "" ? var.log_delivery_configuration : []

    content {

      destination      = lookup(var.log_delivery_configuration, "destination", null)

      destination_type = lookup(var.log_delivery_configuration, "destination_type", null)

      log_format       = lookup(var.log_delivery_configuration, "log_format", null)

      log_type         = lookup(var.log_delivery_configuration, "log_type", null)

    }

  }

  apply_immediately          = lookup(var.elasticache_redis, "apply_immediately", var.elasticache_redis_default["apply_immediately"])

  auto_minor_version_upgrade = lookup(var.elasticache_redis, "auto_minor_version_upgrade", var.elasticache_redis_default["auto_minor_version_upgrade"])

  final_snapshot_identifier  = format("%s-%s", lookup(var.elasticache_redis, "cluster_id"), lookup(var.elasticache_redis, "final_snapshot_identifier", var.elasticache_redis_default["final_snapshot_identifier"]))

  ip_discovery               = lookup(var.elasticache_redis, "ip_discovery", var.elasticache_redis_default["ip_discovery"])

  tags                       = merge(var.default_tags, var.tags)

}



# Redis Cluster Mode with read replica

resource "aws_elasticache_user" "elasticache_user" {

  count         = lookup(var.elasticache_redis, "transit_encryption_enabled", var.elasticache_redis_default["transit_encryption_enabled"]) ? (lookup(var.elasticache_redis, "auth_token", "") != "" ? 1 : 0) : 0

  user_id       = lookup(var.elasticache_user, "user_id")

  user_name     = lookup(var.elasticache_user, "user_name")

  access_string = lookup(var.elasticache_user, "access_string")

  engine        = "REDIS"

  passwords     = [lookup(var.elasticache_user, "passwords")]

  tags          = merge(var.default_tags, var.tags)

}



resource "aws_elasticache_user_group" "elasticache_user_group" {

  count         = lookup(var.elasticache_redis, "transit_encryption_enabled", var.elasticache_redis_default["transit_encryption_enabled"]) ? (lookup(var.elasticache_redis, "auth_token", "") != "" ? 1 : 0) : 0

  engine        = "REDIS"

  user_group_id = lookup(var.elasticache_user, "user_group_id")

  user_ids      = [aws_elasticache_user.elasticache_user.*.user_id[0]]

}



resource "aws_elasticache_replication_group" "elasticache_replication_group" {

  count                      = lookup(var.elasticache_redis, "enable_cluster_mode_disable_redis", var.elasticache_redis_default["enable_cluster_mode_disable_redis"]) || lookup(var.elasticache_redis, "enable_cluster_mode_redis", var.elasticache_redis_default["enable_cluster_mode_redis"]) ? 1 : 0

  description                = lookup(var.elasticache_redis, "replication_group_name")

  replication_group_id       = lookup(var.elasticache_redis, "cluster_id")

  apply_immediately          = lookup(var.elasticache_redis, "apply_immediately", var.elasticache_redis_default["apply_immediately"])

  at_rest_encryption_enabled = lookup(var.elasticache_redis, "at_rest_encryption_enabled", var.elasticache_redis_default["at_rest_encryption_enabled"])

  transit_encryption_enabled = lookup(var.elasticache_redis, "transit_encryption_enabled", var.elasticache_redis_default["transit_encryption_enabled"])

  auth_token                 = lookup(var.elasticache_redis, "transit_encryption_enabled", var.elasticache_redis_default["transit_encryption_enabled"]) ? lookup(var.elasticache_redis, "auth_token", null) : null

  auto_minor_version_upgrade = lookup(var.elasticache_redis, "auto_minor_version_upgrade", var.elasticache_redis_default["auto_minor_version_upgrade"])

  automatic_failover_enabled = lookup(var.elasticache_redis, "enable_cluster_mode_redis", var.elasticache_redis_default["enable_cluster_mode_redis"]) ? true : false

  data_tiering_enabled       = lookup(var.elasticache_redis, "data_tiering_enabled", var.elasticache_redis_default["data_tiering_enabled"])

  engine                     = lookup(var.elasticache_redis, "engine", var.elasticache_redis_default["engine"])

  engine_version             = lookup(var.elasticache_redis, "engine_version", var.elasticache_redis_default["engine_version"])

  final_snapshot_identifier  = format("%s-%s", lookup(var.elasticache_redis, "cluster_id"), lookup(var.elasticache_redis, "final_snapshot_identifier", var.elasticache_redis_default["final_snapshot_identifier"]))

  kms_key_id                 = var.kms_key_id != "" ? var.kms_key_id : null

  dynamic "log_delivery_configuration" {

    for_each = var.log_delivery_configuration != "" ? var.log_delivery_configuration : []

    content {

      destination      = lookup(var.log_delivery_configuration, "destination", null)

      destination_type = lookup(var.log_delivery_configuration, "destination_type", null)

      log_format       = lookup(var.log_delivery_configuration, "log_format", null)

      log_type         = lookup(var.log_delivery_configuration, "log_type", null)

    }

  }

  maintenance_window          = lookup(var.elasticache_redis, "maintenance_window", var.elasticache_redis_default["maintenance_window"])

  multi_az_enabled            = lookup(var.elasticache_redis, "multi_az_enabled", var.elasticache_redis_default["multi_az_enabled"])

  node_type                   = lookup(var.elasticache_redis, "node_type", var.elasticache_redis_default["node_type"])

  notification_topic_arn      = var.notification_topic_arn != "" ? var.notification_topic_arn : null

  num_cache_clusters          = lookup(var.elasticache_redis, "enable_cluster_mode_redis", var.elasticache_redis_default["enable_cluster_mode_redis"]) ? null : lookup(var.elasticache_redis, "num_cache_clusters", var.elasticache_redis_default["num_cache_clusters"])

  num_node_groups             = lookup(var.elasticache_redis, "enable_cluster_mode_redis", var.elasticache_redis_default["enable_cluster_mode_redis"]) ? lookup(var.elasticache_redis, "num_node_groups", var.elasticache_redis_default["num_node_groups"]) : null

  replicas_per_node_group     = lookup(var.elasticache_redis, "enable_cluster_mode_redis", var.elasticache_redis_default["enable_cluster_mode_redis"]) ? lookup(var.elasticache_redis, "replicas_per_node_group", var.elasticache_redis_default["replicas_per_node_group"]) : null

  parameter_group_name        = lookup(var.elasticache_redis, "enable_cluster_mode_redis", var.elasticache_redis_default["enable_cluster_mode_redis"]) ? format("%s.cluster.on", lookup(var.elasticache_redis, "parameter_group_name", var.elasticache_redis_default["parameter_group_name"])) : lookup(var.elasticache_redis, "parameter_group_name", var.elasticache_redis_default["parameter_group_name"])

  port                        = lookup(var.elasticache_redis, "port", var.elasticache_redis_default["port"])

  preferred_cache_cluster_azs = var.preferred_cache_cluster_azs

  security_group_ids          = var.security_group_ids

  snapshot_name               = lookup(var.elasticache_redis, "snapshot_name ", null)

  snapshot_window             = lookup(var.elasticache_redis, "snapshot_window ", var.elasticache_redis_default["snapshot_window"])

  snapshot_retention_limit    = lookup(var.elasticache_redis, "snapshot_retention_limit", var.elasticache_redis_default["snapshot_retention_limit"])

  subnet_group_name           = aws_elasticache_subnet_group.subnet_group.name

  user_group_ids              = lookup(var.elasticache_redis, "transit_encryption_enabled", var.elasticache_redis_default["transit_encryption_enabled"]) && lookup(var.elasticache_redis, "auth_token", "") != "" ? aws_elasticache_user_group.elasticache_user_group.*.id : []

  tags                        = merge(var.default_tags, var.tags)

}






