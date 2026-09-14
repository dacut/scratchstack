-- Seed data for the cloud test suite.
--
-- cloud.quota_units is populated by migration 0017, so only the service the quota tests hang
-- their definitions off is needed here. The region exists so that a regional quota has somewhere
-- to be assigned once the account-quota operations land.
INSERT INTO cloud.regions(region_name) VALUES ('test-region-1');

INSERT INTO cloud.services(service_id, service_dns_name, description)
VALUES ('example', 'example.scratchstack.net', 'A service that exists so quotas have an owner.');

INSERT INTO cloud.service_regions(service_id, region_name) VALUES ('example', 'test-region-1');
