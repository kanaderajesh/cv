# kafka_producer.py

import asyncio
import json
import ssl
from aiokafka import AIOKafkaProducer


class KafkaProducerClient:
    """
    Kafka producer that accepts YAML config object (dict),
    not filename.
    Topic is also read from YAML.
    """

    def __init__(self, config: dict):
        self.config = config
        self.eventhub = self.config["eventhub"]
        self.topic = self.eventhub["topic"]

        self.producer = None
        self.ssl_context = self._build_ssl_context()

    def _build_ssl_context(self):
        ssl_cfg = self.eventhub["ssl"]

        context = ssl.create_default_context(
            cafile=ssl_cfg["ca_file"]
        )

        context.load_cert_chain(
            certfile=ssl_cfg["cert_file"],
            keyfile=ssl_cfg["key_file"]
        )

        return context

    async def start(self):
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.eventhub["bootstrap_servers"],
            security_protocol=self.eventhub.get("security_protocol", "SSL"),
            ssl_context=self.ssl_context,
            client_id=self.eventhub.get("client_id", "python-producer"),
            acks=self.eventhub.get("acks", "all"),
        )

        await self.producer.start()

    async def send(self, message):
        """
        Sends message to topic from YAML config
        """

        if isinstance(message, dict):
            payload = json.dumps(message).encode("utf-8")
        elif isinstance(message, str):
            payload = message.encode("utf-8")
        else:
            payload = message

        return await self.producer.send_and_wait(
            self.topic,
            payload
        )

    async def stop(self):
        if self.producer:
            await self.producer.stop()


# ---------------- Example Usage ----------------

async def main():

    config = {
        "eventhub": {
            "bootstrap_servers": [
                "kafka1.company.net:9093",
                "kafka2.company.net:9093"
            ],
            "topic": "orders-topic",
            "security_protocol": "SSL",
            "client_id": "orders-app",
            "acks": "all",
            "ssl": {
                "ca_file": "/certs/ca.pem",
                "cert_file": "/certs/client.pem",
                "key_file": "/certs/client.key"
            }
        }
    }

    producer = KafkaProducerClient(config)

    await producer.start()

    await producer.send({
        "order_id": 101,
        "status": "created"
    })

    await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())