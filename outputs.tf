output "region" {
    description = "The AWS region to deploy the resources in"
    value = var.region
}
output "key_name" {
    description = "The name of the key pair to use for SSH access to the instance"
    value = var.key_name
}
output "windows_control_node" {
    value = aws_instance.windows_control_node.id
}
output "iis_windows_control_node" {
    value = aws_autoscaling_group.iis_windows_asg.name
}
output "ad_windows_control_node" {
    value = aws_autoscaling_group.ad_windows_asg.name
}
output "file_windows_control_node" {
    value = aws_autoscaling_group.file_windows_asg.name
}