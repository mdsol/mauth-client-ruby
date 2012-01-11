require 'rubygems'
require "bundler/setup"
require 'rack'
require 'rack/mauth'

smart_app = lambda { |env| [200, {'Content-Type' => 'text/plain'}, ["Smart app: Success!\n"]] }

config = {
  :mauth_baseurl => 'http://0.0.0.0:3000',
  :private_key => "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEApr1NrmTQPlwZ4XKSl3bmmDCu0j7ME1goC5YD/XAHqe5pkrEV\nVk6j8gP+Gi/3UypGM/JmzWGSTenDFApkys3VkO7kwOqcHVO1wXTZTKLSUheR3H1p\nN5ZyfUkHrw/LTOm+tA0tNnqQF2FjdGLnY8Pni/3IjyaocKo2i+oKFaxdMO6M9dF+\neQEgVloQcSFPi5gNwgTvAu2urfJKMx+p5LU44A1kqf9NT86sIscF84PssPGHm5IL\n7mFXBmwPFrr4NODp1BsXchFPVIVGVFfHjYnwQLuyFTwfCi2LTr9o7MMuXAJUdtQd\n9ihiuSJwWR+PTkmeNVCs1s30ejHUv3PDCBKXSwIDAQABAoIBADhBQBcpfjS74CN3\nA0xE2lHYgvL+Kt4P7RrTly8HgB5uCIJsanV+/MMnY7C0JC6T4bGfA94hIDpXNvDo\n/M6LmZVXdCg+P0OJvZWydanseScnOpf4W+pcQO5SGFyQ6JdfeW7Hz0xFF547xlE7\nGTRIoTNTATqC4Wt5kgOsh5B+Ycai+Yve89DT2DHHG0xDk6iMEgSO4iFSQhDnoIBJ\nGaJPU2r79q3AGVrHJZUQGmeiKxDNwjxjY9EEGXGTFbADf8lhK7qh/eTJeIRsQ1Wi\nZ1gCVxnzqJdIO7kfZHiVXocpePf0WTfZvM4XqXhUt6EiOXR5TaT5vB1BuNNmBvXQ\nxntDxBECgYEA3DoBNYVr74jsMbcUB1iRHzgSLMw2Z0pQ19SZeF91/tTU6PxGQwaa\nI7etgSzaXFmZ7B6IC64muiu00aQjltnBCIKqMyfOHIOTs79Xordoq5LUWuV0EC1z\nOXpSN4tADkpgHh+qr8yn55Nf+hnR0HpRE+OkTTW+VNN8Ooz80j1APnkCgYEAwdMR\nZDJrlEjYu82ql641P6WNHpSKBCR/6Y27aw7i1n44UDfika4ODiEwkJ+Rjf2+FVVC\n9kz9I9tkjBtoP7BN0ffRvyx607dV9MmRRhJrhDFLAkNZqYobMnE3ihXB+AcDU3rY\neD+cQAHmigwbkkSam2ek1dQZOIZomtXyw2gAQuMCgYAftG4WIXYvjvvKEHxerl5+\nKxlav6+ZYTaQS/goPz4CiOt5+0+2OI4aVEgzT5zELNYfCyo03EaRCNfIUqQZBJJo\nwj70jGd87WhnOUXJlDQKd2IBEAWMiq6K+NQ7UN3Q8N4zmAV/t6v4h9wKaostQ17G\nyUAPKYyUM7ovx7piHhVQqQKBgBls66oeJxiTmcLBDvDIzHll6SYqzBQRCaqEiiJY\nGI+UjSSQwCrmDzfxSKKgHALpV0cLITaYENjkTcNHURyRrxOtE5mlZxNgyGjNDD6J\n6gq0QKeyWA+yazDpwyRdCE3V9ay8v6q+hWusFCblwbQlRba/GNNn+Er+7rfo+uiB\nOw+LAoGARyRQ6azgTT1USjcENcWJYa9sUUQuAwJHfuay1R4j0ufinM/VciPAF08R\nLwT6kd5AqDZ7xyebqp7VrCwD7ttXEj5u+oDxUSUx+v2JV1nUggEoqejPuVGWg5ce\n2XHbr5ULf9PJioDJSs113I8kc7TaXmrNqS5LqMdaxev/XiC/tjg=\n-----END RSA PRIVATE KEY-----\n",
  :app_uuid => 'A',
  :version => 'v1'
}

use Medidata::MAuthMiddleware, config
run smart_app
