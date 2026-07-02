"""Synthetic paramiko deploy fixture A."""
import paramiko

HOST = "10.0.0.8"
USER = "root"
PASS = "placeholder"


def deploy():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS)
    client.exec_command("systemctl restart pihole-FTL")
    sftp = client.open_sftp()
    sftp.put("local.conf", "/opt/app/remote.conf")
    client.exec_command("ufw allow 51820/udp")
    client.exec_command("chmod 600 /opt/app/secret.conf")
