# Auto-detect the caller's public IP when var.my_ip is left unset, so
# nobody has to hardcode/update an IP address by hand (it drifts whenever a
# VPN toggles or someone else runs apply from a different network). An
# explicit var.my_ip still wins when set.

data "http" "my_ip" {
  count = var.my_ip == "" ? 1 : 0

  url = "https://v4.ident.me/"
  request_headers = {
    "User-Agent" = "curl/8.0"
  }
}

locals {
  my_ip = var.my_ip != "" ? var.my_ip : "${chomp(data.http.my_ip[0].response_body)}/32"
}
