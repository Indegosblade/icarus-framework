"""Synthetic deploy helper fixture."""
import paramiko


def restart_services(host="10.0.0.8"):
    client = paramiko.SSHClient()
    client.connect(host, username="root")
    client.exec_command("systemctl restart unbound")
