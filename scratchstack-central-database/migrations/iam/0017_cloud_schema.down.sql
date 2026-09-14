DROP TABLE IF EXISTS cloud.account_quotas;
DROP TABLE IF EXISTS cloud.quota_definitions;
DROP TABLE IF EXISTS cloud.service_regions;
DROP TABLE IF EXISTS cloud.services;
DROP TABLE IF EXISTS cloud.quota_units;
DROP TABLE IF EXISTS cloud.regions;
ALTER TABLE IF EXISTS cloud.partition SET SCHEMA iam;
DROP SCHEMA IF EXISTS cloud;
