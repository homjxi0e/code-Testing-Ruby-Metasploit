# -*- coding: binary -*-

##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##



class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::Telnet
  

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Exploit windows',
      'Description'    => %q{
          the Target windows-10.
        },
      'Author'         => [ 'Gihad <Gihad@yahoo.com>','hak5' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2017-0143'],
          [],
          [],
          [],
      ],
      'Privileged'     => true,
      'Platform'       => 'windows',
      'Payload'        =>
        {
          'Space'       => 200,
          'BadChars'    => "\x00",
          'DisableNops' => true,
        },

      'Targets'        =>
        [
          [ 'Automatic',  { } ],
          [ 'windows-10', { 'Ret' => 0x0804b43c } ],
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Dec 23 2011'))
  end

  def exploit_target
   
  end

end
