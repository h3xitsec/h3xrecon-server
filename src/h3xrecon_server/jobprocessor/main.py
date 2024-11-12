import asyncio
from loguru import logger
from h3xrecon_server.jobprocessor import JobProcessor
from h3xrecon_core import Config

async def main():
    config = Config()
    config.setup_logging()
    logger.info("Starting H3XRecon Job Processor...")
    job_processor = JobProcessor(config)
    await job_processor.start()
    
    try:
        # Keep the data processor running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await job_processor.stop()

if __name__ == "__main__":
    asyncio.run(main())
