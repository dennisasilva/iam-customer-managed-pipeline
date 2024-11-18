variable "repository_type" {
  description = "Select the repository type you want to create a CodeStar connection for"
  type        = string
  default     = "GitHub"
}

variable "s3_bucket_code_bucket" {
  description = "S3 bucket with the initial repository code. Must be created in advance."
  type        = string
  default     = "iam-cx-mng-pipeline-initialcode"
}

variable "s3_bucket_code_key" {
  description = "Name of the zip file with the repository initial code hosted in S3 bucket above"
  type        = string
  default     = "iam-cx-mng-pipeline.zip"
}

variable "repository_name" {
  description = "Name of the GitHub repository"
  type        = string
  default     = "iam-cx-mng-pipeline"
}

variable "repository_owner" {
  description = "Username of the GitHub repository owner"
  type        = string
  default     = "dennisasilva"
}

variable "secret_id" {
  description = "Insert the secret name value here"
  type        = string
  default     = "dev/cx-mgn-pipe/github"
}

variable "naming_convention" {
  description = "Insert the naming convention value here"
  type        = string
  default     = "cx-mng-pipeline"
}
