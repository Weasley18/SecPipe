variable "name" {
  description = "Budget name."
  type        = string
  default     = "secpipe-monthly"
}

variable "monthly_limit_usd" {
  description = "Monthly cost cap in USD."
  type        = number
  default     = 10

  validation {
    condition     = var.monthly_limit_usd > 0 && var.monthly_limit_usd <= 50
    error_message = "This is a demo account: keep the cap between 0 and 50 USD."
  }
}

variable "alert_emails" {
  description = "Addresses that receive budget alerts."
  type        = list(string)

  validation {
    condition     = length(var.alert_emails) > 0
    error_message = "At least one address must receive the alert."
  }
}

variable "tags" {
  description = "Tags applied to the budget."
  type        = map(string)
  default     = {}
}
