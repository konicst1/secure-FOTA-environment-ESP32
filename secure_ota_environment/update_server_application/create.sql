create table firmware_image (id integer not null, device_type varchar(255), firmware_length bigint, image_file varchar(255), manifest_length bigint, primary key (id)) engine=InnoDB;
