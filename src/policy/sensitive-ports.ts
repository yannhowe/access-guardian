/**
 * Ports that stay a finding when an ingress rule is open to the world.
 * The ranges 137-139 and 5900-5903 are expanded. 80 and 443 are not on this list.
 */
export const SENSITIVE_PORTS: readonly number[] = Object.freeze([
  20, 21, 22, 23, 53, 69, 111, 135, 137, 138, 139, 161, 162, 389, 445, 636, 1433, 1521, 2049, 2181, 2375, 2376,
  2379, 2380, 3306, 3389, 5432, 5672, 5900, 5901, 5902, 5903, 5984, 5985, 5986, 6379, 6443, 7000, 7001, 8080, 8200,
  8443, 8500, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 10250, 11211, 15672, 27017, 27018,
]);
