# Network Security Project - Attack to PLC

## Instructions to run the project

- ###  OPENPLC container:
    - #### TO CREATE AND RUN A NEW CONTAINER
    ```bash
    sudo docker run --name plc2 tuttas/openplc_v3
    ```
    
    - #### TO RUN EXISTING CONTAINER
    ```bash
    sudo docker start plc2
    ```
    
- ### APP container:
  ```bash
  cd ./app
  ```
    - #### TO CREATE IMAGE (DO ONLY ONCE)
      ```bash
        sudo docker build -t app .
      ```
    - #### TO RUN CONTAINER
      If there is already a container, first you have to delete it:
      ```bash
        sudo docker rm app
      ```
      Then, we can run the new container:
      ```bash
        sudo docker run -it -v .:/app --name app app
      ```
      The flag -v .:/app allows the files export_nmap and export_plc to be visible from the host machine.
