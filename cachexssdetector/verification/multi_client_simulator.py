"""
Multi-client Simulator for CacheXSSDetector.
Simulates multiple clients to perform concurrent load testing and scanning.
"""

import asyncio
from typing import List, Callable, Any, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)

class MultiClientSimulator:
    """
    Simulates multiple clients performing concurrent requests.
    """

    def __init__(self, concurrency: int = 5, delay: float = 0.1):
        """
        Initialize the simulator.
        
        Args:
            concurrency (int): Number of concurrent clients
            delay (float): Delay between requests per client in seconds
        """
        self.concurrency = concurrency
        self.delay = delay

    async def simulate_clients(
        self,
        task_func: Callable[[int], Any],
        total_requests: int,
        *args,
        **kwargs
    ) -> List[Any]:
        """
        Simulate multiple clients performing the given task function.
        
        Args:
            task_func (Callable[[int], Any]): Async function to execute per request, receives client id
            total_requests (int): Total number of requests to perform
            *args: Additional positional arguments for task_func
            **kwargs: Additional keyword arguments for task_func
            
        Returns:
            List[Any]: List of results from task_func calls
        """
        results = []
        semaphore = asyncio.Semaphore(self.concurrency)

        async def client_task(client_id: int):
            async with semaphore:
                try:
                    result = await task_func(client_id, *args, **kwargs)
                    return result
                except Exception as e:
                    logger.error(f"Client {client_id} task failed: {str(e)}")
                    return None

        tasks = []
        for i in range(total_requests):
            tasks.append(asyncio.create_task(client_task(i)))

        for task in asyncio.as_completed(tasks):
            res = await task
            results.append(res)
            await asyncio.sleep(self.delay)

        return results

if __name__ == "__main__":
    # Example usage
    import random

    async def example_task(client_id: int):
        await asyncio.sleep(random.uniform(0.1, 0.5))
        return f"Client {client_id} completed"

    async def main():
        simulator = MultiClientSimulator(concurrency=3, delay=0.2)
        results = await simulator.simulate_clients(example_task, total_requests=10)
        for r in results:
            print(r)

    asyncio.run(main())
