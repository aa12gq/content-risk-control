#!/bin/bash

echo "测试服务健康状态..."
curl -s http://localhost:8080/api/v1/health
echo -e "\n"

echo "测试正常内容..."
curl -s -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"content":"这是一段正常的文本，描述了美好的一天。","user_id":"user123","scene":"post"}' | jq .
echo -e "\n"

echo "测试敏感内容..."
curl -s -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"content":"你真是个傻逼，滚开！","user_id":"user123","scene":"comment"}' | jq .
echo -e "\n"

echo "测试上下文检查（骚扰行为）..."
curl -s -X POST http://localhost:8080/api/v1/check_with_context \
  -H "Content-Type: application/json" \
  -d '{
    "content": "别那么高冷嘛，我就想跟你聊聊天而已，给个微信呗？",
    "user_id": "user789",
    "scene": "chat",
    "context_items": [
      {
        "content": "嗨，我们能交个朋友吗？",
        "user_id": "user789",
        "time": '"$(date +%s -d "-5 minutes")"'
      },
      {
        "content": "不好意思，我不感兴趣，请不要打扰我。",
        "user_id": "user123",
        "time": '"$(date +%s -d "-4 minutes")"'
      },
      {
        "content": "为什么不想跟我聊天呢？给个机会吧。",
        "user_id": "user789",
        "time": '"$(date +%s -d "-3 minutes")"'
      },
      {
        "content": "请不要再打扰我了。",
        "user_id": "user123",
        "time": '"$(date +%s -d "-2 minutes")"'
      }
    ]
  }' | jq . 