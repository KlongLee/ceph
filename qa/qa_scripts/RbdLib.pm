#! /usr/bin/perl
=head1 NAME

RbdLib.pm - Perl Module that contains the functions used by CLI script for testing RBD.

=cut

package RbdLib;
use Cwd;
use Exporter;
@ISA = 'Exporter';
@EXPORT_OK = qw(perform_action create_image resize_image rename_image copy_image list_image info_image export_image import_image remove_image create_snapshots rollback_snapshots purge_snapshots list_snapshots remove_snapshot rbd_map rbd_unmap rbd_showmapped display_result _pre_clean_up _post_clean_up _create_rados_pool display_ceph_os_info $RADOS_MKPOOL $RADOS_RMPOOL $RBD_CREATE $RBD_RESIZE $RBD_INFO $RBD_REMOVE $RBD_RENAME $RBD_MV $RBD_LS $RBD_LIST $RBD_CLONE $RBD_EXPORT $RBD_IMPORT $RBD_CP $RBD_COPY $SNAP_CREATE $SNAP_LS $SNAP_LIST $SNAP_ROLLBACK $SNAP_PURGE $SNAP_REMOVE $POOL_RM_SUCCESS $POOL_MK_SUCCESS $RBD_EXISTS_ERR $RBD_WATCH $RBD_MAP $RBD_UNMAP $RBD_SHOWMAPPED get_command_output debug_msg );
use Pod::Usage();
use Getopt::Long();

use strict;
use warnings;

$|=1;

# variables
our $TC_CNT         = " ";
our $PASS_CNT       = 0;
our $FAIL_CNT       = 0;
our $RADOS_MKPOOL   = "rados mkpool";
our $RADOS_RMPOOL   = "rados rmpool";
our $RBD_CREATE     = "rbd create";
our $RBD_RESIZE     = "rbd resize";
our $RBD_INFO       = "rbd info";
our $RBD_REMOVE     = "rbd rm";
our $RBD_RENAME     = "rbd rename";
our $RBD_MV         = "rbd mv";
our $RBD_LS         = "rbd ls";
our $RBD_LIST       = "rbd list";
our $RBD_CLONE      = "rbd clone";
our $RBD_EXPORT     = "rbd export";
our $RBD_IMPORT     = "rbd import";
our $RBD_COPY       = "rbd copy";
our $RBD_CP         = "rbd cp";
our $SNAP_CREATE    = "rbd snap create";
our $SNAP_LIST      = "rbd snap list";
our $SNAP_LS        = "rbd snap ls";
our $SNAP_ROLLBACK  = "rbd snap rollback";
our $SNAP_REMOVE    = "rbd snap rm";
our $SNAP_PURGE     = "rbd snap purge";
our $RBD_WATCH      = "rbd watch";
our $RBD_MAP        = "sudo rbd map";
our $RBD_UNMAP      = "sudo rbd unmap";
our $RBD_SHOWMAPPED = "rbd showmapped";

#====Error messages========================

our $RBD_RM_ERROR      = "image name was not specified";
our $SNAP_LS_ERROR     = "snap name was not specified";
our $SNAP_RM_ERROR     = "remove failed";
our $SNAP_ROLLBACK_ERR = "rollback failed";
our $RBD_CP_ERROR      = "error: destination image name";
our $RBD_EXISTS_ERR    = "exists";
our $RBD_RENAME_ERROR  = "rename error";
our $RBD_DELETE_ERROR  = "delete error";
our $RBD_NO_IMAGE      = "error opening image";
our $RBD_POOL_ERROR    = "error opening pool";
our $RBD_INT_ERR       = "expected integer";
our $RBD_ARG_ERR       = "requires an argument";
our $RBD_EXP_ERR       = "export error";
our $RBD_IMP_ERR       = "import failed";
our $RBD_MAP_ERR       = "add failed";
our $RBD_UNMAP_ERR     = "remove failed";
our $RBD_INFO_SNAP_ERR = "error setting snapshot context";

#=======Success messages=======================

our $POOL_MK_SUCCESS       = "successfully created pool";
our $POOL_RM_SUCCESS       = "successfully deleted pool";
our $RBD_RM_SUCCESS        = "Removing image: 100%";
our $RBD_CP_SUCCESS        = "Image copy: 100%";
our $RBD_RESIZE_SUCCESS    = "Resizing image: 100%";
our $RBD_EXP_SUCCESS       = "Exporting image: 100%";
our $RBD_IMP_SUCCESS       = "Importing image: 100%";
our $SNAP_ROLLBACK_SUCCESS = "Rolling back to snapshot: 100%";
our $SNAP_PURGE_SUCCESS    = "Removing all snapshots: 100%";

#===========Variables used in the script========

our $test_log      = "logfile.txt";
our $success_file  = "test_completed.txt";
our $log_file     = "log.txt";
our $exec_cmd;
our $PASS_FLAG;
our $MSG;
our $rbd_imp_file     = "test_file";
our $exp_file         = "rbd_test_file1";
our $exp_file1        = "rbd_test_file2";
our $rbd_imp_test     = "new_test_file";
our $img_name         = "test_img";
our $pool_name;

sub _post_clean_up {
    my $exec_cmd = get_command_output(
"rm -rf $img_name $rbd_imp_file $rbd_imp_test $exp_file $exp_file1"
    );
}

sub _pre_clean_up {
    my $exec_cmd = get_command_output(
"rm -rf logfile.txt log.txt test_completed.txt"
    );
}
 
sub perform_action {
    my ( $action, $cmd_args, $option ) = @_;
    my $command = frame_command( $action, $cmd_args, $option );
    my $cmd_op = get_command_output($command);
    validate_cmd_output( $cmd_op, $action, $cmd_args, $option );
}

sub pass {
    my ($comment) = @_;
    print "Comment required." unless length $comment;
    chomp $comment;
    print_border2();
    print "Test case: $TC_CNT PASSED - $comment \n";
    print_border2();
    $PASS_CNT++;
    $PASS_FLAG = "TRUE";
    $MSG = "$comment";
}

sub fail {
    my ($comment) = @_;
    print "Comment required." unless length $comment;
    chomp $comment;
    print_border2();
    print "Test case: $TC_CNT FAILED - $comment \n";
    print_border2();
    $FAIL_CNT++;
    $PASS_FLAG = "FALSE";
    $MSG = "$comment";
}

sub debug_msg {
    my ($comment,$is_debug) = @_;
    print "Comment required." unless length $comment;
    chomp $comment;
    print_border3();
    if (!$is_debug){
         print "DEBUG: $comment \n";
    } else {
         print "$comment \n";
    }
    print_border3();
}

sub print_border {
    print "=" x 90 . "\n";
}

sub print_border2 {
    print "~" x 90 . "\n";
}

sub print_border3 {
    print "+" x 90 . "\n";
}

sub banner {
    my ($string) = @_;
    chomp $string;
    print_border();
    print $string, "\n";
    print_border();
}

sub display_result {
    banner("TEST RESULTS");
    banner(
"No. of test cases passed:$PASS_CNT\nNo. of test cases failed:$FAIL_CNT\n"
    );
}

sub get_command_output {
    my $cmd_output = shift;
    open( FH, ">>$test_log" );
    print FH "*" x 90 . "\n";
    print FH "\"$cmd_output\"\n";
    my $exec_cmd = `$cmd_output 2>&1`;
    print FH "$exec_cmd\n";
    print FH "*" x 90 . "\n";
    close(FH);
    return $exec_cmd;
}

sub frame_command {
    my ( $action, $cmd_args, $option ) = @_;
    my @command_set = split( /,/, $cmd_args );
    my $command = join( ' --', @command_set );
    $command = "$action $command";
    return $command;
}

sub check_if_listed {
    my ( $chk_cmd, $check_arg, $cmd, $args ) = @_;
    my $check_op = get_command_output($chk_cmd);
    if ( $check_op =~ /$check_arg/ ) {
        pass("$cmd $args passed");
    }
    else {
        fail("$cmd $args failed");
    }
}

sub check_if_not_listed {
    my ( $chk_cmd, $check_arg, $cmd, $args ) = @_;
    my $check_op = get_command_output($chk_cmd);
    if ( $check_op =~ /$check_arg/ ) {
        fail("$cmd $args failed");
    } else {
        pass("$cmd $args passed");
    }
}

sub validate_cmd_output {
    $TC_CNT++; 
    $PASS_FLAG      = "FALSE";
    $MSG            = " ";
    my ( $arg, $snap, $arg1, $parg );
    my $snaps;
    my ( $cmd_op, $act, $args, $test_flag ) = @_;
    if ( !$test_flag ) {
        if ( ( $act =~ /$RBD_CREATE/ ) && ( !$cmd_op ) ) {
            $arg = ( split /,/, $args )[0];
            $parg = ( split /,/, $args )[1];
            $pool_name = ( split / /, $parg )[1];
            check_if_listed( "$RBD_LS $pool_name", $arg, $act , $args);
        }
        elsif (( ( $act =~ /$RBD_RENAME/ ) || ( $act =~ /$RBD_MV/ ) )
            && ( !$cmd_op ) )
        {
            $arg = ( split /\//, $args )[-1];
            $pool_name = ( split /\//, $args )[0];
            check_if_listed( "$RBD_LS $pool_name", $arg, $act, $args );
        }
        elsif ( ( $act =~ /$SNAP_CREATE/ ) && ( !$cmd_op ) ) {
            $snaps = ( split / /,  $args )[1];
            $arg   = ( split / /, $args )[2];
            check_if_listed( "$SNAP_LS $arg", $snaps, $act, $args );
        }
        elsif ( ( $act =~ /$SNAP_REMOVE/ ) && ( !$cmd_op ) ) {
            $snaps = ( split /\@/, $args )[-1];
            $arg1  = ( split /\@/, $args )[-2];
            $arg   = ( split /\//, $arg1 )[-1];
	    $pool_name = ( split /\@/,$args )[0];
            check_if_not_listed( "$SNAP_LS $pool_name", $snaps , $act, $args);
        }
        elsif (( $act =~ /$SNAP_PURGE/ )
            && ( $cmd_op =~ /$SNAP_PURGE_SUCCESS/ ) )
        {
            pass("$act $args passed");
        }
        elsif ( $act =~ /$RBD_INFO/ ) {
            $arg = ( split /\//, $args )[-1];
            my $rbd_img_quoted = "\'$arg\'";
            pass("$act $args passed")
              if ( $cmd_op =~ /rbd image $rbd_img_quoted/ );
        }
        elsif ( ( $act =~ /$RBD_REMOVE/ ) && ( $cmd_op =~ /$RBD_RM_SUCCESS/ ) )
        {
            $pool_name = ( split /\//, $args )[0];
            my $img_name = ( split /\//, $args )[1];
            check_if_not_listed( "$RBD_LS $pool_name",$img_name , $act, $args );
        }
        elsif (( $act =~ /$RBD_RESIZE/ )
            && ( $cmd_op =~ /$RBD_RESIZE_SUCCESS/ ) )
        {
            pass("$act $args passed");
        }
        elsif (( ( $act =~ /$RBD_COPY/ ) || ( $act =~ /$RBD_CP/ ) )
            && ( $cmd_op =~ /$RBD_CP_SUCCESS/ ) )
        {
            pass("$act $args passed");
        }
        elsif (
            ( $act =~ /$RBD_EXPORT/ )
            && (   ( $cmd_op =~ /$RBD_EXP_SUCCESS/ )
                || ( $cmd_op =~ /$RBD_EXISTS_ERR/ ) )
          )
        {
            pass("$act $args passed");
        }
        elsif (
            ( $act =~ /$RBD_IMPORT/ )
            && (   ( $cmd_op =~ /$RBD_IMP_SUCCESS/ )
                || ( $cmd_op =~ /$RBD_EXISTS_ERR/ ) )
          )
        {
            pass("$act $args passed");
        }
        elsif (( $act =~ /$SNAP_ROLLBACK/ )
            && ( $cmd_op =~ /$SNAP_ROLLBACK_SUCCESS/ ) )
        {
            pass("$act $args passed");
        }
        elsif ( ( $act =~ /$RBD_SHOWMAPPED/ ) && ( $cmd_op =~ /$img_name/ ) ) {
            pass("$act $args passed");
        }
        elsif ( ( $act =~ /$RBD_MAP/ ) && ( $cmd_op !~ /./ ) ) {
            pass("$act $args passed");
        }
        elsif ( ( $act =~ /$RBD_UNMAP/ ) && ( $cmd_op !~ /$RBD_UNMAP_ERR/ ) ) {
            pass("$act $args passed");
        }
        else {
            if ( $cmd_op =~ /$RBD_EXISTS_ERR/ ) {
                pass("$act $args $RBD_EXISTS_ERR");
            }
            else {
                fail("$act $args failed");
            }
        }
    }
    elsif ( ( $test_flag == 1 ) && ( $cmd_op =~ /$RBD_EXISTS_ERR/ ) ) {
        pass("Already exists: $act $args passed");
    }
    elsif (
        ( $test_flag == 2 )
        && (   ( $cmd_op =~ /$RBD_RENAME_ERROR/ )
            || ( $cmd_op =~ /$RBD_DELETE_ERROR/ )
            || ( $cmd_op =~ /$RBD_NO_IMAGE/ )
            || ( $cmd_op =~ /$RBD_POOL_ERROR/ )
            || ( $cmd_op =~ /$RBD_INT_ERR/ )
            || ( $cmd_op =~ /$RBD_ARG_ERR/ )
            || ( $cmd_op =~ /$RBD_RM_ERROR/ )
            || ( $cmd_op =~ /$SNAP_LS_ERROR/ )
            || ( $cmd_op =~ /$SNAP_RM_ERROR/ )
            || ( $cmd_op =~ /$RBD_CP_ERROR/ )
            || ( $cmd_op =~ /$RBD_EXP_ERR/ )
            || ( $cmd_op =~ /$RBD_IMP_ERR/ )
            || ( $cmd_op =~ /$SNAP_ROLLBACK_ERR/ )
            || ( $cmd_op =~ /$RBD_MAP_ERR/ )
            || ( $cmd_op =~ /$RBD_UNMAP_ERR/ )
            || ( $cmd_op =~ /$RBD_INFO_SNAP_ERR/ ) )
      )
    {
        pass("negative case: $act $args passed");
    }
    elsif ( ( $test_flag == 3 ) && ( $cmd_op =~ /usage/ ) ) {
        pass("negative case: $act $args passed");
    }
    else {
        fail("negative case:$act $args failed");
    }
    log_results();
}

# Test Script execution result
sub log_results
{
	if ( $PASS_FLAG eq "TRUE" ) {
            open( TC, '>>test_completed.txt' );
            close(TC);
            open( TC, '>>log.txt' );
	    print TC "[Success] Test Case $TC_CNT $MSG\n";
            close(TC);
	}
	else {
            open( TC, '>>test_completed.txt' );
            close(TC);
            open( TC, '>>log.txt' );
	    print TC "[Failure] Test Case $TC_CNT $MSG\n";
            close(TC);
	}
}

sub ceph_os_info
{
        my $ceph_v = get_command_output ( "ceph -v" );
        my @ceph_arr = split(" ",$ceph_v);
        $ceph_v = "Ceph Version:   $ceph_arr[2]";
        my $os_distro = get_command_output ( "lsb_release -d" );
        my @os_arr = split(":",$os_distro);
        $os_distro = "Linux Flavor:$os_arr[1]";
        return ($ceph_v, $os_distro);
}

sub display_ceph_os_info
{
	my ($vceph, $vos) = ceph_os_info();
        my $msg = "The Tests are running on";
        debug_msg ( "$msg\n$vos$vceph",1 );
	open( TC, '>>log.txt' );
        print TC "[Log] $vceph\n";
	close (TC);
}
1;
