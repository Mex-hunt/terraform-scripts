
variable "elasticache_redis" {

  type        = map(any)

  description = "Values for elasticcache params."

}



variable "elasticache_redis_default" {

  default = {

    enable_single_node_redis          = false

    enable_cluster_mode_disable_redis = false

    enable_cluster_mode_redis         = false

    engine                            = "redis"

    node_type                         = "cache.m4.large"

    num_cache_nodes                   = 1

    parameter_group_name              = "default.redis7"

    engine_version                    = "7.0"

    port                              = 6379

    snapshot_retention_limit          = 1

    snapshot_window                   = "18:00-23:00"

    network_type                      = "ipv4"

    maintenance_window                = "sun:05:00-sun:09:00"

    apply_immediately                 = false

    auto_minor_version_upgrade        = true

    ip_discovery                      = "ipv4"

    az_mode                           = "single-az"

    final_snapshot_identifier         = "finalsnap"

    at_rest_encryption_enabled        = true

    transit_encryption_enabled        = false

    data_tiering_enabled              = false

    multi_az_enabled                  = false

    num_cache_clusters                = 1

    replicas_per_node_group           = 1

    num_node_groups                   = 1

  }

}



variable "security_group_ids" {

  type        = list(any)

  description = "List of security group names to associate with this cache cluster."

  default     = []

}



variable "tags" {

  type        = map(any)

  description = "Maps of tags to assing to the resources."

  default = {

    deployed_by = "terraform"

  }

}



variable "notification_topic_arn" {

  type        = string

  description = "ARN of an SNS topic to send ElastiCache notifications to."

  default     = ""

}



variable "log_delivery_configuration" {

  type        = list(map(any))

  description = "Specifies the destination and format of Redis SLOWLOG or Redis Engine Log"

  default     = []

}



variable "kms_key_id" {

  type        = string

  description = "The ARN of the key that you wish to use if encrypting at rest."

  default     = ""

}



variable "preferred_cache_cluster_azs" {

  type        = list(any)

  description = "List of EC2 availability zones in which the replication group's cache clusters will be created."

  default     = []

}



variable "subnet_ids" {

  type        = list(any)

  description = "List of subnet ids to use by the redis node."

  default     = []

}



variable "elasticache_user" {

  type        = map(any)

  description = "Input param values for elasticache_user"

  default     = {}

}




