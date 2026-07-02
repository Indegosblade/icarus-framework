"""Synthetic paramiko deploy fixture B."""
import paramiko


def connect():
    client = paramiko.SSHClient()
    client.connect("10.0.0.8", username="admin", password="placeholder")
    client.exec_command("systemctl restart unbound")
    client.exec_command("cp /opt/app/a.conf /opt/app/b.conf")
