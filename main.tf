provider "aws" {
    region = var.region
}
locals {
    instance_name  = "security-access-project"
    vpc_cidr       = "10.0.0.0/16"
    azs            = slice(data.aws_availability_zones.available.names, 0, 2)
}
data "aws_availability_zones" "available" {}

#############################################
#                 VPC                       #
#############################################
# Se crea una VPC con sus subredes públicas y privadas.
# Crear la VPC
resource "aws_vpc" "main" {
    cidr_block           = local.vpc_cidr
    instance_tenancy     = "default"
    enable_dns_support   = true
    enable_dns_hostnames = true
    tags = {
        Name = "vpc-${local.instance_name}"
    }
}
#############################################
#             Public Subnet                 #
#############################################
# Crear Subredes Públicas
resource "aws_subnet" "public_subnet1" {
    vpc_id            = aws_vpc.main.id
    cidr_block        = "10.0.0.0/24"
    availability_zone = "${var.region}a"
    tags = {
        Name = "subnet-public-1-${var.region}"
    }
}

#############################################
#            Internet Gateway               #
#############################################
# Crear el Internet Gateway
resource "aws_internet_gateway" "igw" {
    vpc_id = aws_vpc.main.id
    tags = {
        Name = "igw-${local.instance_name}"
    }
}

#############################################
#           Public Route Table              #
#############################################
# Crear la tabla de rutas públicas
resource "aws_route_table" "public_route_table" {
    vpc_id = aws_vpc.main.id
    tags = {
        Name = "rtb-public-${local.instance_name}"
    }
}

resource "aws_route" "public_route" {
    route_table_id         = aws_route_table.public_route_table.id
    destination_cidr_block = "0.0.0.0/0"
    gateway_id             = aws_internet_gateway.igw.id
}

# Asociar subredes públicas con la tabla de rutas públicas
resource "aws_route_table_association" "public_subnet1_association" {
    subnet_id      = aws_subnet.public_subnet1.id
    route_table_id = aws_route_table.public_route_table.id
}

#############################################
#               Network ACL                 #
#############################################
resource "aws_network_acl" "public_acl" {
    vpc_id     = aws_vpc.main.id
    subnet_ids = [
        aws_subnet.public_subnet1.id
    ]
    tags = {
        Name = "acl-public-${var.region}"
    }
}
# Entrada: permitir SSH (22)
resource "aws_network_acl_rule" "inbound_ssh" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 100
    egress         = false
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 22
    to_port        = 22
}

# Entrada: permitir RDP (3389)
resource "aws_network_acl_rule" "inbound_rdp" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 110
    egress         = false
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 3389
    to_port        = 3389
}

# Entrada: permitir respuesta a conexiones ya establecidas
resource "aws_network_acl_rule" "inbound_ephemeral" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 120
    egress         = false
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 1024
    to_port        = 65535
}

# Entrada: permitir HTTP (80)
resource "aws_network_acl_rule" "inbound_http" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 130
    egress         = false
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 80
    to_port        = 80
}

# Entrada: permitir HTTPS (443)
resource "aws_network_acl_rule" "inbound_https" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 140
    egress         = false
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 443
    to_port        = 443
}

# Entrada: permitir L2TP/IPsec IKE (500)
resource "aws_network_acl_rule" "inbound_l2tp_ike" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 150
    egress         = false
    protocol       = "udp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 500
    to_port        = 500
}

# Entrada: permitir L2TP (1701)
resource "aws_network_acl_rule" "inbound_l2tp" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 160
    egress         = false
    protocol       = "udp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 1701
    to_port        = 1701
}

# Entrada: permitir L2TP/IPsec NAT-T (4500)
resource "aws_network_acl_rule" "inbound_l2tp_nat_t" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 170
    egress         = false
    protocol       = "udp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 4500
    to_port        = 4500
}

# Entrada: permitir Radius Auth (1812)
resource "aws_network_acl_rule" "inbound_radius_auth" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 180
    egress         = false
    protocol       = "udp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 1812
    to_port        = 1812
}

# Entrada: permitir Radius Account (1813)
resource "aws_network_acl_rule" "inbound_radius_account" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 190
    egress         = false
    protocol       = "udp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 1813
    to_port        = 1813
}

# Entrada: permitir DNS (53)
resource "aws_network_acl_rule" "inbound_dns" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 200
    egress         = false
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 53
    to_port        = 53
}

# Entrada: permitir LDAP (389)
resource "aws_network_acl_rule" "inbound_ldap" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 210
    egress         = false
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 389
    to_port        = 389
}

# Entrada: permitir ICMP
resource "aws_network_acl_rule" "inbound_icmp" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 220
    egress         = false
    protocol       = "icmp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = -1
    to_port        = -1
}

# Salida: permitir SSH
resource "aws_network_acl_rule" "outbound_ssh" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 100
    egress         = true
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 22
    to_port        = 22
}

# Salida: permitir RDP
resource "aws_network_acl_rule" "outbound_rdp" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 110
    egress         = true
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 3389
    to_port        = 3389
}

# Salida: permitir conexiones efímeras (respuesta)
resource "aws_network_acl_rule" "outbound_ephemeral" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 120
    egress         = true
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 1024
    to_port        = 65535
}

# Salida: permitir HTTP (80)
resource "aws_network_acl_rule" "outbound_http" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 130
    egress         = true
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 80
    to_port        = 80
}

# Salida: permitir HTTPS (443)
resource "aws_network_acl_rule" "outbound_https" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 140
    egress         = true
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 443
    to_port        = 443
}

# Salida: permitir L2TP/IPsec IKE (500)
resource "aws_network_acl_rule" "outbound_l2tp_ike" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 150
    egress         = true
    protocol       = "udp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 500
    to_port        = 500
}

# Salida: permitir L2TP (1701)
resource "aws_network_acl_rule" "outbound_l2tp" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 160
    egress         = true
    protocol       = "udp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 1701
    to_port        = 1701
}

# Salida: permitir L2TP/IPsec NAT-T (4500)
resource "aws_network_acl_rule" "outbound_l2tp_nat_t" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 170
    egress         = true
    protocol       = "udp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 4500
    to_port        = 4500
}

# Salida: permitir Radius Auth (1812)
resource "aws_network_acl_rule" "outbound_radius_auth" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 180
    egress         = true
    protocol       = "udp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 1812
    to_port        = 1812
}

# Salida: permitir Radius Account (1813)
resource "aws_network_acl_rule" "outbound_radius_account" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 190
    egress         = true
    protocol       = "udp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 1813
    to_port        = 1813
}

# Salida: permitir DNS (53)
resource "aws_network_acl_rule" "outbound_dns" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 200
    egress         = true
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 53
    to_port        = 53
}

# Salida: permitir LDAP (389)
resource "aws_network_acl_rule" "outbound_ldap" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 210
    egress         = true
    protocol       = "tcp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = 389
    to_port        = 389
}

# Salida: permitir ICMP
resource "aws_network_acl_rule" "outbound_icmp" {
    network_acl_id = aws_network_acl.public_acl.id
    rule_number    = 220
    egress         = true
    protocol       = "icmp"
    rule_action    = "allow"
    cidr_block     = "0.0.0.0/0"
    from_port      = -1
    to_port        = -1
}

#############################################
#             Security Group                #
#############################################
#-----------Windows Control Node-----------
resource "aws_security_group" "windows_access" {
    vpc_id      = aws_vpc.main.id
    name        = "windows-${var.region}-sg"
    description = "Allow SSH, HTTPS, HTTP access"

    ingress {
        description = "SSH access for Ansible playbooks"
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "HTTP access"
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "HTTPS access"
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
    
    ingress {
        description = "ICMP access"
        from_port   = -1
        to_port     = -1
        protocol    = "icmp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        description = "Allow all outbound traffic"
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
    tags = {
        Name = "sg-${local.instance_name}-windows"
    }
}
#------------Windows VPN Server------------
resource "aws_security_group" "vpn_windows_access" {
    vpc_id      = aws_vpc.main.id
    name        = "vpn_windows-${var.region}-sg"
    description = "Allow winRM, RDP, L2TP/IPsec access"

    ingress {
        description = "WinRM access"
        from_port   = 5985      # WinRM HTTP
        to_port     = 5985
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "RDP access"
        from_port   = 3389
        to_port     = 3389
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "L2TP/IPsec IKE access"
        from_port   = 500
        to_port     = 500
        protocol    = "udp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "L2TP/IPsec L2TP access"
        from_port   = 1701
        to_port     = 1701
        protocol    = "udp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "L2TP/IPsec NAT-T access"
        from_port   = 4500
        to_port     = 4500
        protocol    = "udp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "ICMP access"
        from_port   = -1
        to_port     = -1
        protocol    = "icmp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        description = "Allow all outbound traffic"
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
    tags = {
        Name = "vpn-sg-${local.instance_name}-windows"
    }
}
#------------Windows AD Server-------------
resource "aws_security_group" "ad_windows_access" {
    vpc_id      = aws_vpc.main.id
    name        = "ad-windows-${var.region}-sg"
    description = "Allow winRM, RDP access"

    ingress {
        description = "WinRM access"
        from_port   = 5985      # WinRM HTTP
        to_port     = 5985
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "RDP access"
        from_port   = 3389
        to_port     = 3389
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "ICMP access"
        from_port   = -1
        to_port     = -1
        protocol    = "icmp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "LDAP access"
        from_port   = 389
        to_port     = 389
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "DNS access"
        from_port   = 53
        to_port     = 53
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        description = "Allow all outbound traffic"
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
    tags = {
        Name = "ad-sg-${local.instance_name}-windows"
    }
}
#-----------Windows Radius Server-------------
resource "aws_security_group" "radius_windows_access" {
    vpc_id      = aws_vpc.main.id
    name        = "radius-windows-${var.region}-sg"
    description = "Allow winRM, RDP access"

    ingress {
        description = "WinRM access"
        from_port   = 5985      # WinRM HTTP
        to_port     = 5985
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "RDP access"
        from_port   = 3389
        to_port     = 3389
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "Radius Auth access"
        from_port   = 1812
        to_port     = 1812
        protocol    = "udp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "Radius Account access"
        from_port   = 1813
        to_port     = 1813
        protocol    = "udp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "DNS access"
        from_port   = 53
        to_port     = 53
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "LDAP access"
        from_port   = 389
        to_port     = 389
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "ICMP access"
        from_port   = -1
        to_port     = -1
        protocol    = "icmp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        description = "Allow all outbound traffic"
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
    tags = {
        Name = "radius-sg-${local.instance_name}-windows"
    }
}

#############################################
#              Instance EC2                 #
#############################################
#-----------Windows Control Node------------
resource "aws_instance" "windows_control_node" {
    ami = var.linux_ami
    instance_type = var.instance_type
    key_name = var.key_name

    subnet_id = aws_subnet.public_subnet1.id
    security_groups = [aws_security_group.windows_access.id]
    associate_public_ip_address = true

    root_block_device {
        volume_size = 20
        volume_type = "gp2"
        encrypted   = true
    }

    iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name
    
    user_data = base64encode(file("windows_control_node.sh"))

    monitoring = true

    provisioner "file" {
        source = "./ssh-code.pem"
        destination = "/home/ubuntu/ssh-code.pem"
    }

    provisioner "remote-exec" {
        inline = ["chmod 400 /home/ubuntu/ssh-code.pem"]
    }

    connection {
        type = "ssh"
        user = "ubuntu"
        private_key = file("./ssh-code.pem")
        host = aws_instance.windows_control_node.public_ip
    }

    tags = {
        Name = "windows-control-node-${local.instance_name}"
    }
}
#-------------Windows VPN Server--------------
resource "aws_launch_template" "vpn_windows_template" {
    name_prefix   = "vpn-windows-template-"
    image_id      = var.windows_ami
    instance_type = var.instance_type
    
    key_name      = var.key_name

    iam_instance_profile {
        name = aws_iam_instance_profile.ec2_instance_profile.name
    }
    network_interfaces {
        associate_public_ip_address = true
        security_groups             = [aws_security_group.vpn_windows_access.id]
    }

    monitoring {
        enabled = true
    }

    block_device_mappings {
        device_name = "/dev/sda1"
        ebs {
            volume_size = 30
            volume_type = "gp2"
            encrypted   = true
        }
    }

    user_data = base64encode(file("/vpn_server_windows.ps1"))

    tag_specifications {
        resource_type = "instance"
        tags = {
            Name = "windows-${local.instance_name}"
            Role = "vpn"
        }
    }

    lifecycle {
        create_before_destroy = true
    }
}
#---------Windows Active Directory-----------
resource "aws_launch_template" "ad_windows_template" {
    name_prefix   = "ad-windows-template-"
    image_id      = var.windows_ami
    instance_type = var.instance_type
    
    key_name      = var.key_name

    iam_instance_profile {
        name = aws_iam_instance_profile.ec2_instance_profile.name
    }
    network_interfaces {
        associate_public_ip_address = true
        security_groups             = [aws_security_group.ad_windows_access.id]
    }

    monitoring {
        enabled = true
    }

    block_device_mappings {
        device_name = "/dev/sda1"
        ebs {
            volume_size = 30
            volume_type = "gp2"
            encrypted   = true
        }
    }

    user_data = base64encode(file("/ad_server_windows.ps1"))

    tag_specifications {
        resource_type = "instance"
        tags = {
            Name = "windows-${local.instance_name}"
            Role = "ad"
        }
    }

    lifecycle {
        create_before_destroy = true
    }
}
#---------Windows Radius Server-----------
resource "aws_launch_template" "radius_windows_template" {
    name_prefix   = "radius-windows-template-"
    image_id      = var.windows_ami
    instance_type = var.instance_type
    
    key_name      = var.key_name

    iam_instance_profile {
        name = aws_iam_instance_profile.ec2_instance_profile.name
    }
    network_interfaces {
        associate_public_ip_address = true
        security_groups             = [aws_security_group.radius_windows_access.id]
    }

    monitoring {
        enabled = true
    }

    block_device_mappings {
        device_name = "/dev/sda1"
        ebs {
            volume_size = 30
            volume_type = "gp2"
            encrypted   = true
        }
    }

    user_data = base64encode(file("/radius_server_windows.ps1"))

    tag_specifications {
        resource_type = "instance"
        tags = {
            Name = "windows-${local.instance_name}"
            Role = "radius"
        }
    }

    lifecycle {
        create_before_destroy = true
    }
}

#############################################
#            Auto Scaling Group             #
#############################################
#------------Windows VPN Server------------
resource "aws_autoscaling_group" "vpn_windows_asg" {
    name                = "vpn-windows-asg-${local.instance_name}"

    desired_capacity    = 1
    max_size            = 3
    min_size            = 1

    health_check_type   = "EC2"
    health_check_grace_period = 300

    vpc_zone_identifier = [aws_subnet.public_subnet1.id]

    launch_template {
        id      = aws_launch_template.vpn_windows_template.id
        version = "$Latest"
    }

    tag {
        key                 = "Name"
        value               = "vpn-windows-${local.instance_name}"
        propagate_at_launch = true
    }
    
    tag {
        key                 = "Role"
        value               = "vpn"
        propagate_at_launch = true
    }

    lifecycle {
        create_before_destroy = true
    }
}
#---------Windows AD Server------------
resource "aws_autoscaling_group" "ad_windows_asg" {
    name                = "ad-windows-asg-${local.instance_name}"

    desired_capacity    = 1
    max_size            = 3
    min_size            = 1

    health_check_type   = "EC2"
    health_check_grace_period = 300

    vpc_zone_identifier = [aws_subnet.public_subnet1.id]

    launch_template {
        id      = aws_launch_template.ad_windows_template.id
        version = "$Latest"
    }

    tag {
        key                 = "Name"
        value               = "ad-windows-${local.instance_name}"
        propagate_at_launch = true
    }
    
    tag {
        key                 = "Role"
        value               = "ad"
        propagate_at_launch = true
    }

    lifecycle {
        create_before_destroy = true
    }
}
#------------Windows Radius Server-------------
resource "aws_autoscaling_group" "radius_windows_asg" {
    name                = "radius-windows-asg-${local.instance_name}"

    desired_capacity    = 1
    max_size            = 3
    min_size            = 1

    health_check_type   = "EC2"
    health_check_grace_period = 300

    vpc_zone_identifier = [aws_subnet.public_subnet1.id]

    launch_template {
        id      = aws_launch_template.radius_windows_template.id
        version = "$Latest"
    }

    tag {
        key                 = "Name"
        value               = "radius-windows-${local.instance_name}"
        propagate_at_launch = true
    }
    
    tag {
        key                 = "Role"
        value               = "radius"
        propagate_at_launch = true
    }

    lifecycle {
        create_before_destroy = true
    }
}

###############################################
#                 IAM Role                    #
###############################################
resource "aws_iam_role" "ec2_role" {
    name = "ec2-readonly-role"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
        {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Principal = {
                Service = "ec2.amazonaws.com"
            }
        }
        ]
    })
}

###############################################
#                IAM Policies                 #
###############################################
resource "aws_iam_policy" "ec2_get_password_data" {
    name        = "EC2GetPasswordDataPolicy"
    description = "Permite llamar a ec2:GetPasswordData"
    policy = jsonencode({
        Version = "2012-10-17",
        Statement = [
            {
                Effect = "Allow",
                Action = [
                "ec2:GetPasswordData"
                ],
                Resource = "*"
            }
        ]
    })
}

###############################################
#              IAM Attachments                #
###############################################
resource "aws_iam_role_policy_attachment" "ec2_readonly_policy" {
    role       = aws_iam_role.ec2_role.name
    policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}
resource "aws_iam_role_policy_attachment" "cloudwatch_agent_attach" {
    role        = aws_iam_role.ec2_role.name
    policy_arn  = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}
resource "aws_iam_role_policy_attachment" "attach_get_password_data" {
    role       = aws_iam_role.ec2_role.name
    policy_arn = aws_iam_policy.ec2_get_password_data.arn
}

###############################################
#               IAM Profile                   #
###############################################
resource "aws_iam_instance_profile" "ec2_instance_profile" {
    name = "ec2-instance-profile"
    role = aws_iam_role.ec2_role.name
}