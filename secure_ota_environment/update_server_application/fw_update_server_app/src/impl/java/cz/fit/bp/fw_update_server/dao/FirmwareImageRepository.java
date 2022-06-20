package cz.fit.bp.fw_update_server.dao;

import cz.fit.bp.fw_update_server.entity.FirmwareImage;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

public interface FirmwareImageRepository extends CrudRepository<FirmwareImage, Integer> {


    public FirmwareImage findFirstByDeviceTypeOrderByIdDesc(String deviceTypr);

}
