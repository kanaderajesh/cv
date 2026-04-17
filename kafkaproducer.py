# kafka_producer.py

import asyncio
import ssl
from aiokafka import AIOKafkaProducer


class KafkaProducerClient:
    """
    Kafka Producer Library

    - Accepts YAML config object (dict)
    - Topic taken from YAML
    - Supports bulk messages
    - Input message = list of key/value pairs
    - Converts to comma-separated string
    """

    def __init__(self, config: dict):
        self.config = config
        self.eventhub = config["eventhub"]
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

    def _convert_to_csv(self, item: dict) -> bytes:
        """
        Convert dict to comma separated string

        Example:
        {"id":1,"name":"raj"} -> b"1,raj"
        """
        values = [str(v) for v in item.values()]
        csv_line = ",".join(values)
        return csv_line.encode("utf-8")

    async def send_bulk(self, messages: list):
        """
        messages = [
            {"id":1,"name":"raj"},
            {"id":2,"name":"john"}
        ]

        Sends each record as:
        1,raj
        2,john
        """

        tasks = []

        for item in messages:
            payload = self._convert_to_csv(item)

            task = self.producer.send(
                self.topic,
                payload
            )

            tasks.append(task)

        results = await asyncio.gather(*tasks)
        return results

    async def stop(self):
        if self.producer:
            await self.producer.stop()


# ---------------- Example ----------------

async def main():

    config = {
        "eventhub": {
            "bootstrap_servers": [
                "kafka1.company.net:9093"
            ],
            "topic": "employee-topic",
            "security_protocol": "SSL",
            "client_id": "bulk-loader",
            "acks": "all",
            "ssl": {
                "ca_file": "/certs/ca.pem",
                "cert_file": "/certs/client.pem",
                "key_file": "/certs/client.key"
            }
        }
    }

    messages = [
        {"id": 1, "name": "Raj", "city": "London"},
        {"id": 2, "name": "John", "city": "Leeds"},
        {"id": 3, "name": "Sam", "city": "Bristol"}
    ]

    producer = KafkaProducerClient(config)

    await producer.start()

    await producer.send_bulk(messages)

    await producer.stop()


if __name__ == "__main__":
    asyncio.run(main())