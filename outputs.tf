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
output "vpn_windows_control_node" {
    value = aws_autoscaling_group.vpn_windows_asg.name
}
output "ad_windows_control_node" {
    value = aws_autoscaling_group.ad_windows_asg.name
}
output "radius_windows_control_node" {
    value = aws_autoscaling_group.radius_windows_asg.name
}