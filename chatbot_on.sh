systemctl daemon-reload
systemctl enable ssh-chat-server.service
systemctl enable ai-message-sender.service
systemctl start ssh-chat-server.service
systemctl start ai-message-sender.service
