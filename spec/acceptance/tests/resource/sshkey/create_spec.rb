require 'spec_helper_acceptance'

RSpec.context 'sshkeys: Create' do
  let(:keyname) { "pl#{rand(999_999).to_i}" }

  # FIXME: This is bletcherous
  let(:macos_version) { fact_on(agent, 'os.macosx.version.major') }
  let(:ssh_known_hosts) do
    if ['10.9', '10.10'].include? macos_version
      '/etc/ssh_known_hosts'
    else
      '/etc/ssh/ssh_known_hosts'
    end
  end

  before(:each) do
    osx_agents.each do |agent|
      # The 'cp' might fail because the source file doesn't exist
      on(
        agent,
        "cp -fv #{ssh_known_hosts} /tmp/ssh_known_hosts",
        acceptable_exit_codes: [0, 1],
      )
    end
  end

  after(:each) do
    osx_agents.each do |agent|
      # Is it present?
      rc = on(
        agent,
        '[ -e /tmp/ssh_known_hosts ]',
        accept_all_exit_codes: true,
      )
      if rc.exit_code == 0
        # It's present, so restore the original
        on(
          agent,
          "mv -fv /tmp/ssh_known_hosts #{ssh_known_hosts}",
          accept_all_exit_codes: true,
        )
      else
        # It's missing, which means there wasn't one to backup; just
        # delete the one we laid down
        on(
          agent,
          "rm -fv #{ssh_known_hosts}",
          accept_all_exit_codes: true,
        )
      end
    end
  end

  osx_agents.each do |agent|
    it "#{agent} should add an SSH key to the correct ssh_known_hosts file on OS X/macOS (PUP-5508)" do
      # Is it even there?
      rc = on(
        agent,
        "[ ! -e #{ssh_known_hosts} ]",
        acceptable_exit_codes: [0, 1],
      )
      if rc.exit_code == 1
        # If it's there, it should be empty
        on(agent, "cat #{ssh_known_hosts}") do |_res|
          expect(stdout).to be_empty
        end
      end

      args = [
        'ensure=present',
        'key=how_about_the_key_of_c',
        'type=ssh-rsa',
      ]
      on(agent, puppet_resource('sshkey', keyname.to_s, args))

      on(agent, "cat #{ssh_known_hosts}") do |_rc|
        expect(stdout).to include(keyname.to_s)
      end
    end
  end
end
