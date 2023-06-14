class google_password_notifier (
  String[1] $version,
  String[1] $app_password,
  String[1] $service_account_email,
  String[1] $delegated_email,
  String[1] $private_key,
  Integer   $treshold,
  String[1] $sender_email,
  String[1] $group = root,
  String[1] $user = root,
  String[1] $python_version = '3.9',
) {
  $package_name = 'google_password_notifier'
  $executable_name = $package_name
  $package_root_dir = "/opt/${package_name}"
  $config_file = "${package_root_dir}/config.yaml"
  $exec_file =  "/usr/local/bin/${package_name}"
  $exec_args = $config_file
  $version_dir = $package_root_dir
  $service_account_p12 = "${package_root_dir}/secret.p12"

  isolated_python_package { $package_name:
    package_ensure    => $version,
    python_version    => $python_version,
    directory         => $package_root_dir,
    create_executable => true,
    executable_name   => $executable_name,
  }

  ->file { $service_account_p12:
    ensure  => file,
    owner   => $user,
    group   => $group,
    content => $private_key,
  }

  ->file { $config_file:
    ensure  => file,
    owner   => $user,
    group   => $group,
    content => epp(
      "${module_name}/config.yaml.epp",
      {
        'app_password'          => $app_password,
        'service_account_email' => $service_account_email,
        'delegated_email'       => $delegated_email,
        'treshold'              => $treshold,
        'sender_email'          => $sender_email,
        'service_account_p12'   => $service_account_p12
      }
    ),
  }
  ->scheduler::job { $package_name:
    command       => "/bin/bash -c  \". ${package_root_dir}/virtualenv/bin/activate && google-password-notifier -c ${config_file}\"",
    cron_schedule => '10 10 * * *',
    user          => $user,
    tries         => 1,
  }
}
