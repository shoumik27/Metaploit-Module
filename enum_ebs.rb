class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'AWS Public EBS Snapshot Enumerator',
      'Description'    => %q{
        This module enumerates publicly accessible EBS snapshots in a specified AWS region.
      },
      'Author'         => [ 'Shoumik Chandra' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('REGION', [true, 'The AWS region to target', 'us-east-1']),
        OptString.new('OWNER_ID', [false, 'The AWS account ID of the snapshot owner (optional)']),
        OptBool.new('SHOW_DETAILS', [false, 'Show detailed snapshot metadata', false])
      ])
  end

  def run
    aws_region = datastore['REGION']
    owner_id = datastore['OWNER_ID']
    show_details = datastore['SHOW_DETAILS']

    begin
      ebs_client = Aws::EC2::Client.new(region: aws_region)
      filter_options = {
        filters: [
          {
            name: 'public', 
            values: ['true']
          }
        ]
      }

      filter_options[:owner_ids] = [owner_id] if owner_id

      snapshots = ebs_client.describe_snapshots(filter_options)

      if snapshots.snapshots.empty?
        print_status('No public EBS snapshots found.')
      else
        snapshots.snapshots.each do |snapshot|
          print_good("Snapshot ID: #{snapshot.snapshot_id}")
          if show_details
            print_status("  Description: #{snapshot.description}")
            print_status("  Creation Date: #{snapshot.start_time}")
            print_status("  Size: #{snapshot.volume_size} GB")
          end
        end
      end
    rescue Aws::Errors::ServiceError => e
      print_error("Error fetching snapshots: #{e.message}")
    end
  end
end
