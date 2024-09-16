OPENPLC container:
    TO CREATE NEW 
        sudo docker run --name plc2 tuttas/openplc_v3 
    TO RUN EXISTING 
        sudo docker start plc2

APP container:
    cd ./app
    TO CREATE IMAGE (DO ONLY ONCE)
        sudo docker build -t app .
    TO RUN CONTAINER
        sudo docker rm app                                  (to delete previously created container)
        sudo docker run -it -v .:/app --name app app        (to create new container)