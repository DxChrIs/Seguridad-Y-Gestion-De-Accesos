variable "region" {
    description = "The AWS region to deploy the resources in"
    type        = string
    default     = "us-east-1"
}
variable "instance_type" {
    description = "The type of EC2 instance to create"
    type        = string
    default     = "t3.medium"
}
variable "linux_ami" {
    description = "The AMI ID to use for the EC2 instance"
    type        = string
    default     = "ami-084568db4383264d4" # Amazon Linux 2 AMI (HVM), SSD Volume Type
}
variable "windows_ami" {
    description = "The AMI ID to use for the EC2 instance"
    type        = string
    default     = "ami-0db3480be03d8d01c" # Windows Server 2022 Base
}
variable "openvpn_ami" {
    description = "The AMI ID to use for the EC2 instance"
    type        = string
    default     = "ami-06e5a963b2dadea6f" # OpenVPN Access Server
}
variable "key_name" {
    description = "The name of the key pair to use for SSH access to the instance"
    type        = string
    default     = "ssh-code"
}