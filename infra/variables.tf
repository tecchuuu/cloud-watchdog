# Inputs you can change without editing the other files.
# Example: tofu apply -var="idle_hours=2"

variable "aws_region" {
  description = "Region the Watchdog itself is deployed in"
  type        = string
  default     = "us-east-1"
}

variable "regions" {
  description = "Regions the scanner checks"
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}

variable "scan_schedule" {
  description = "How often EventBridge runs the scanner"
  type        = string
  default     = "rate(1 day)"
}

variable "idle_hours" {
  description = "An EC2 must run this long under the CPU limit to count as idle (use 2 for the demo)"
  type        = number
  default     = 24
}
