#import multiprocessing
import environ
import uvicorn

from .app.main import app

env = environ.Env()

host: str = env.str("HOSTNAME", default="0.0.0.0")

port: int = env.int("PORT", default=8888)
reload: bool = env.bool('RELOAD', default=False)
keyfile: str = '/certs/localhost.key'
certfile: str = '/certs/localhost.crt'

workers: int = env.int('WORKERS', default=1)

if "__name__" == "__main__":
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=reload,
        ssl_keyfile=keyfile,
        ssl_certfile=certfile,
        workers=workers,
        ssl_version=2,
    )
