terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# For production, use S3 backend:
# terraform {
#   backend "s3" {
#     bucket = "imladris-terraform-state"
#     key    = "platform/terraform.tfstate"
#     region = "us-east-1"
#     dynamodb_table = "imladris-terraform-locks"
#     encrypt = true
#   }
# }