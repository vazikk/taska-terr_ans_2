# taska-terr_ans_2

Обновил файл terraform/main: <br>
```
provider "aws" {
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
  region     = var.aws_region
}

resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr
  tags       = { Name = "main" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "main" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public1_sub_cide
  availability_zone       = var.AZ-1
  map_public_ip_on_launch = true
  tags                    = { Name = "public" }
}

resource "aws_subnet" "public2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public2_sub_cide
  availability_zone       = var.AZ-2
  map_public_ip_on_launch = true
  tags                    = { Name = "public2" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id
  
  tags = {
    Name = "nat-gateway"
  }
  
  depends_on = [aws_internet_gateway.main]
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.priv_sub_cide
  availability_zone = var.AZ-1
  tags              = { Name = "private" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = var.cidr-0
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "public" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = var.cidr-0
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Name = "private" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public2" {
  subnet_id      = aws_subnet.public2.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# Security Groups
resource "aws_security_group" "vpn" {
  name   = "vpn"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.cidr-0]
  }

  ingress {
    from_port   = 1194
    to_port     = 1194
    protocol    = "udp"
    cidr_blocks = [var.cidr-0]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr-0]
  }
  tags = { Name = "vpn" }
}

resource "aws_security_group" "private" {
  name   = "private"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.vpn.id]
  }

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]  # Разрешает весь трафик внутри VPC
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]  # Разрешает весь трафик внутри VPC
  }

  ingress {
    from_port   = 9100
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr-0]
  }
  tags = { Name = "private" }
}

resource "aws_security_group" "alb" {
  name   = "alb"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.cidr-0]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr-0]
  }
  tags = { Name = "alb" }
}

resource "aws_instance" "vpn" {
  ami                    = var.ami
  instance_type          = var.aws_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.vpn.id]
  key_name               = "taski" # ПОМЕНЯЙ НА СВОЙ КЛЮЧ


  tags = { Name = "vpn" }
}

resource "aws_instance" "private" {
  ami                    = var.ami
  instance_type          = var.aws_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.private.id]
  key_name               = "taski" # ПОМЕНЯЙ НА СВОЙ КЛЮЧ

  tags = { Name = "private" }
}

# ALB
resource "aws_lb" "main" {
  name               = "main-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public.id, aws_subnet.public2.id]
  tags               = { Name = "main-alb" }
}

resource "aws_lb_target_group" "nginx" {
  name     = "nginx-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check { path = "/" }
}

resource "aws_lb_target_group" "grafana" {
  name     = "grafana-tg"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check { path = "/api/health" }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nginx.arn
  }
}

resource "aws_lb_target_group_attachment" "nginx" {
  target_group_arn = aws_lb_target_group.nginx.arn
  target_id        = aws_instance.private.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "grafana" {
  target_group_arn = aws_lb_target_group.grafana.arn
  target_id        = aws_instance.private.id
  port             = 3000
}


# Security Group для Redis кластера
resource "aws_security_group" "redis" {
  name   = "redis"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    from_port   = 16379
    to_port     = 16379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    from_port   = 26379
    to_port     = 26379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    from_port   = 9121
    to_port     = 9121
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    from_port   = 9100
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.vpn.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr-0]
  }
  tags = { Name = "redis" }
}

# Security Group для Prometheus
resource "aws_security_group" "prometheus" {
  name   = "prometheus"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    from_port   = 9100
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.vpn.id]
  }

  egress {
    from_port   = 9100
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 9121
    to_port     = 9121
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.cidr-0]
  }
  tags = { Name = "prometheus" }
}


# Redis Cluster Instances
resource "aws_instance" "redis1" {
  ami                    = var.ami
  instance_type          = var.aws_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.redis.id]
  key_name               = "taski"
  private_ip             = "10.0.2.10"

  tags = { 
    Name = "redis1"
    Role = "redis"
  }
}


resource "aws_instance" "redis2" {
  ami                    = var.ami
  instance_type          = var.aws_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.redis.id]
  key_name               = "taski"
  private_ip             = "10.0.2.11"

  tags = { 
    Name = "redis2"
    Role = "redis"
  }
}


resource "aws_instance" "redis3" {
  ami                    = var.ami
  instance_type          = var.aws_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.redis.id]
  key_name               = "taski"
  private_ip             = "10.0.2.12"

  tags = { 
    Name = "redis3"
    Role = "redis"
  }
}


# Prometheus Instance
resource "aws_instance" "prometheus" {
  ami                    = var.ami
  instance_type          = var.aws_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.prometheus.id]
  key_name               = "taski"
  private_ip             = "10.0.2.20"

  tags = { 
    Name = "prometheus"
    Role = "monitoring"
  }
}
```

<br>

Дальше добавил машины в hosts: <br>
```
[vpn]
vpn ansible_host=44.204.241.199 ansible_user=ubuntu

[private]
private ansible_host=10.0.2.254 ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/taski.pem ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p -i ~/.ssh/taski.pem ubuntu@44.204.241.199"'

[redis]
redis1 ansible_host=10.0.2.10 ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/taski.pem ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p -i ~/.ssh/taski.pem ubuntu@44.204.241.199"'
redis2 ansible_host=10.0.2.11 ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/taski.pem ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p -i ~/.ssh/taski.pem ubuntu@44.204.241.199"'
redis3 ansible_host=10.0.2.12 ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/taski.pem ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p -i ~/.ssh/taski.pem ubuntu@44.204.241.199"'


[prometheus]
prometheus ansible_host=10.0.2.20 ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/taski.pem ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p -i ~/.ssh/taski.pem ubuntu@44.204.241.199"'

[monitoring]
prometheus
private

[redis_cluster:children]
redis
```

<br>

Дпльше добавил 3 роли в Ansible (node_exporter, prometheus, redis) <br>

redis/tasks/main.yml <br>
```
---
- name: Update apt cache
  apt:
    update_cache: yes
    cache_valid_time: 3600

- name: Install Redis and Sentinel
  apt:
    name: 
      - redis-server
      - redis-sentinel
    state: present

- name: Create Redis configuration directory
  file:
    path: /etc/redis
    state: directory
    mode: 0755

- name: Create Redis log directory
  file:
    path: /var/log/redis
    state: directory
    owner: redis
    group: redis
    mode: '0755'

- name: Create Redis run directory
  file:
    path: /var/run/redis
    state: directory
    owner: redis
    group: redis
    mode: '0755'

- name: Configure Redis
  template:
    src: redis.conf.j2
    dest: /etc/redis/redis.conf
  notify: restart redis

- name: Configure Sentinel
  template:
    src: sentinel.conf.j2
    dest: /etc/redis/sentinel.conf
  notify: restart sentinel

- name: Set correct permissions for Sentinel config
  file:
    path: /etc/redis/sentinel.conf
    owner: redis
    group: redis
    mode: '0644'

- name: Start and enable Redis
  systemd:
    name: redis-server
    state: started
    enabled: yes

- name: Start and enable Sentinel
  systemd:
    name: redis-sentinel
    state: started
    enabled: yes

- name: Wait for Redis to start
  wait_for:
    port: 6379
    host: 127.0.0.1
    delay: 5
    timeout: 30

- name: Setup replication (replicas only)
  command: redis-cli -h 127.0.0.1 REPLICAOF 10.0.2.10 6379
  when: inventory_hostname != "10.0.2.10"

- name: Download and install redis-exporter
  get_url:
    url: https://github.com/oliver006/redis_exporter/releases/download/v1.57.0/redis_exporter-v1.57.0.linux-amd64.tar.gz
    dest: /tmp/redis_exporter.tar.gz
    mode: '0755'

- name: Extract redis-exporter
  unarchive:
    src: /tmp/redis_exporter.tar.gz
    dest: /usr/local/bin/
    remote_src: yes
    owner: root
    group: root
    mode: '0755'
    extra_opts: [--strip-components=1]

- name: Create systemd service for redis-exporter
  template:
    src: redis-exporter.service.j2
    dest: /etc/systemd/system/redis-exporter.service
  notify: restart redis-exporter

- name: Start and enable redis-exporter
  systemd:
    name: redis-exporter
    state: started
    enabled: yes
    daemon_reload: yes
```
 
 <br>
 
redis/handlers/main.yml <br>
```
- name: restart redis
  systemd:
    name: redis-server
    state: restarted

- name: restart sentinel
  systemd:
    name: redis-sentinel
    state: restarted

- name: restart redis-exporter
  systemd:
    name: redis-exporter
    state: restarted
```

<br>

redis/templates/redis.conf: <br>
```
bind 0.0.0.0
port 6379
protected-mode no
dir /var/lib/redis
dbfilename dump.rdb
appendonly yes
replica-read-only yes
maxmemory 256mb
maxmemory-policy allkeys-lru
loglevel notice
logfile /var/log/redis/redis-server.log
daemonize yes
```

<br>

redis/templates/sentinel.conf: <br>
```
port 26379
bind 0.0.0.0
protected-mode no
daemonize yes
pidfile /var/run/redis/redis-sentinel.pid
logfile /var/log/redis/redis-sentinel.log

sentinel monitor mymaster 10.0.2.10 6379 2
sentinel down-after-milliseconds mymaster 5000
sentinel failover-timeout mymaster 10000
sentinel parallel-syncs mymaster 1

dir /var/lib/redis
```

<br>

redis/templates/redis-exporter: <br>
```
[Unit]
Description=Redis Exporter
After=network.target

[Service]
Type=simple
User=redis
ExecStart=/usr/local/bin/redis_exporter -redis.addr redis://localhost:6379 -web.listen-address :9121
Restart=always

[Install]
WantedBy=multi-user.target
```

<br>

Теперь роль PROMETHEUS <br>

ptometheus/tasks/main.yml: <br>
```
---
- name: Create prometheus user
  user:
    name: prometheus
    system: yes
    shell: /bin/false

- name: Create directories
  file:
    path: "{{ item }}"
    state: directory
    owner: prometheus
    group: prometheus
  loop:
    - /etc/prometheus
    - /var/lib/prometheus

- name: Download Prometheus
  get_url:
    url: https://github.com/prometheus/prometheus/releases/download/v2.51.2/prometheus-2.51.2.linux-amd64.tar.gz
    dest: /tmp/prometheus.tar.gz

- name: Extract Prometheus
  unarchive:
    src: /tmp/prometheus.tar.gz
    dest: /tmp/
    remote_src: yes

- name: Install Prometheus binaries
  copy:
    src: "/tmp/prometheus-2.51.2.linux-amd64/{{ item }}"
    dest: "/usr/local/bin/{{ item }}"
    owner: prometheus
    group: prometheus
    mode: '0755'
    remote_src: yes
  loop:
    - prometheus
    - promtool

- name: Install Prometheus configuration
  template:
    src: prometheus.yml.j2
    dest: /etc/prometheus/prometheus.yml
    owner: prometheus
    group: prometheus

- name: Install systemd service
  template:
    src: prometheus.service.j2
    dest: /etc/systemd/system/prometheus.service

- name: Start Prometheus service
  systemd:
    name: prometheus
    state: started
    enabled: yes
    daemon_reload: yes
```
<br>

prometheus/templates/prometheus.yml: <br>
```
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node_exporter'
    static_configs:
      - targets: 
        - '10.0.2.10:9100'
        - '10.0.2.11:9100' 
        - '10.0.2.12:9100'
        - '10.0.2.20:9100'
        - '10.0.2.254:9100'

  - job_name: 'redis_exporter'
    static_configs:
      - targets:
        - '10.0.2.10:9121'
        - '10.0.2.11:9121'
        - '10.0.2.12:9121'
```

<br>

prometheus/templates/promeyheus.service: <br>
```
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
    --config.file /etc/prometheus/prometheus.yml \
    --storage.tsdb.path /var/lib/prometheus/ \
    --web.console.templates=/etc/prometheus/consoles \
    --web.console.libraries=/etc/prometheus/console_libraries

[Install]
WantedBy=multi-user.target
```


Теперь конфиг роли node-exporter <br>

node_exporter/tasks/main: <br>
```
---
- name: Create node_exporter user
  user:
    name: node_exporter
    system: yes
    shell: /bin/false

- name: Download Node Exporter
  get_url:
    url: https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz
    dest: /tmp/node_exporter.tar.gz

- name: Extract Node Exporter
  unarchive:
    src: /tmp/node_exporter.tar.gz
    dest: /usr/local/bin/
    remote_src: yes
    owner: node_exporter
    group: node_exporter
    mode: '0755'
    extra_opts: [--strip-components=1]

- name: Install systemd service
  template:
    src: node_exporter.service.j2
    dest: /etc/systemd/system/node_exporter.service

- name: Start Node Exporter service
  systemd:
    name: node_exporter
    state: started
    enabled: yes
    daemon_reload: yes
```

node_exporter/templates/node_exporter.service: <br>
```
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
```







