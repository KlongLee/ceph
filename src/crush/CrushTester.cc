
#include "CrushTester.h"

//chi squared stuff
#include <math.h>

#ifdef HAVE_BOOST_RANDOM_DISCRETE_DISTRIBUTION
# include <boost/math/distributions/chi_squared.hpp>
# include <boost/accumulators/statistics/variance.hpp>
# include <boost/accumulators/accumulators.hpp>
# include <boost/accumulators/statistics/stats.hpp>

//random number generator
# include <boost/random/mersenne_twister.hpp>
# include <boost/random/discrete_distribution.hpp>

// needed to compute chi squared value
using boost::math::chi_squared;
using boost::accumulators::stats;
using boost::accumulators::variance;
using boost::accumulators::accumulator_set;

// create a random number generator to simulate placements

// use the mersenne twister as our seed generator
typedef boost::mt19937 generator;

generator gen(42); // repeatable
//generator gen(static_cast<unsigned int>(std::time(0))); // non-repeatable (ish)
#endif


void CrushTester::set_device_weight(int dev, float f)
{
  int w = (int)(f * 0x10000);
  if (w < 0)
    w = 0;
  if (w > 0x10000)
    w = 0x10000;
  device_weight[dev] = w;
}

int CrushTester::test()
{
  if (min_rule < 0 || max_rule < 0) {
    min_rule = 0;
    max_rule = crush.get_max_rules() - 1;
  }
  if (min_x < 0 || max_x < 0) {
    min_x = 0;
    max_x = 1023;
  }

  // get the ID's of active buckets
  vector<int> bucket_ids;
  vector<int> buckets_above_devices;
  int num_buckets_active = 0;

  // check that all the devices we think we have are actually in buckets
  int num_devices_active = 0;
  for (int o = 0; o < crush.get_max_devices(); o++){
    if (!crush.check_item_present(o))
      device_weight[o] = 0;
    else
      num_devices_active++;
  }
  
  if (down_ratio_marked){
    for (int i = 1; i <= crush.get_max_buckets(); i++ ){

      int id = -1 - i;

      if (crush.get_bucket_weight(id) > 0){
        bucket_ids.push_back(id);
        num_buckets_active++;
      }
    }

    // possible debugging statement
    //err << "number of buckets with devices" << num_buckets_active << std::endl;


    // get the number of buckets that are one level above a device
    int num_eligible_buckets = 0;

    for (int i = 0; i < num_buckets_active; i++){
      // grab the first child object of a bucket and check if it's ID is less than 0
      int id = bucket_ids[i];
      int first_child = crush.get_bucket_item(id, 0); // returns the ID of the bucket or device

      // possible debugging statement
      //err << "bucket ID " << id << " has first child " << first_child << std::endl;

      if (first_child >= 0){
        buckets_above_devices.push_back(id);
        num_eligible_buckets++;
      }
    }

    // possible debugging statement
    //err << "number of eligible buckets " << num_eligible_buckets << std::endl;

    // calculate how many buckets and devices we need to reap...
    int num_buckets_to_visit = (int) (mark_down_bucket_ratio * num_eligible_buckets);
    int num_devices_to_visit = (int) (mark_down_device_ratio * num_devices_active);

    for (int i = 0; i < num_buckets_to_visit; i++){
      int id = buckets_above_devices[i];
      int local_devices_to_visit = (int) (mark_down_device_ratio*crush.get_bucket_size(id));

      // possible debugging statement
      //err << "device " << id << " is set to mark down " << local_devices_to_visit << " devices" << std::endl;

      for (int o = 0; o < local_devices_to_visit; o++){
        int item = crush.get_bucket_item(id, o);

        // the following two statements are NOT equivalent because if we adjust the item weight we spread the change over the remaining
        // buckets which is a change we can detect in the chi squared testing, we need to decide which behavior to use
        //crush.adjust_item_weightf(g_ceph_context, item, 0.0); // parent bucket weight unchanged
        //crush.set_bucket_item_weightf(id, item, 0.0);       // parent bucket weight reduced by the weight of the lost device

       // possible debugging statement
       //err << "device in position " << o << " in bucket " << id << " now has weight " << crush.get_bucket_item_weight(id, o) << std::endl;

       device_weight[item] = 0; // we really shouldn't have to do this if things worked perfectly... FIXME
       num_devices_to_visit--;
       num_devices_active--;
      }
    }

    if (num_devices_to_visit > 0)
      err << "warning not all requested devices marked out" << std::endl;
  }



  // allow for the user to mark a range of devices down
  if (down_range_marked) {
    for (int o = mark_down_start; o <= (mark_down_start + down_range); o++) {
      device_weight[o] = 0;
      num_devices_active--;
    }
  }


  // all osds in
  vector<__u32> weight;
  for (int o = 0; o < crush.get_max_devices(); o++)
    if (device_weight.count(o))
      weight.push_back(device_weight[o]);
    else
      weight.push_back(0x10000);
  if (output_utilization_all)
    err << "devices weights (hex): " << hex << weight << dec << std::endl;

  if (output_choose_tries)
    crush.start_choose_profile();
  
  for (int r = min_rule; r < crush.get_max_rules() && r <= max_rule; r++) {
      
    if (!crush.rule_exists(r)) {
      if (output_statistics)
        err << "rule " << r << " dne" << std::endl;
      continue;
    }
    int minr = min_rep, maxr = max_rep;
    if (min_rep < 0 || max_rep < 0) {
      minr = crush.get_rule_mask_min_size(r);
      maxr = crush.get_rule_mask_max_size(r);
    }
    

    if (output_statistics)
      err << "rule " << r << " (" << crush.get_rule_name(r)
      << "), x = " << min_x << ".." << max_x
      << ", numrep = " << minr << ".." << maxr
      << std::endl;

    for (int nr = minr; nr <= maxr; nr++) {
      vector<int> per(crush.get_max_devices());
      map<int,int> sizes;
      
      int num_objects = ((max_x - min_x) + 1);
      float num_devices = (float) per.size(); // get the total number of devices, better to cast as a float here 

#ifdef HAVE_BOOST_RANDOM_DISCRETE_DISTRIBUTION
      float test_chi_statistic = 0.0; // our observed chi squared statistic
      
      // look up the maximum expected chi squared statistic for the 5% and 1% confidence levels
      float chi_statistic_five_percent = quantile(complement(chi_squared(num_devices_active-1), 0.05));
      float chi_statistic_one_percent = quantile(complement(chi_squared(num_devices_active-1), 0.01));
#endif
      
      // create a map to hold batch-level placement information
      map<int, vector<int> > batchPer; 
      vector <float> deviceTestChi (per.size() );
      
      int objects_per_batch = num_objects / num_batches;
      
      int batch_min = min_x;
      int batch_max = min_x + objects_per_batch - 1;
      
      
#ifdef HAVE_BOOST_RANDOM_DISCRETE_DISTRIBUTION
      // placeholders for the reference values, we will probably SEGFAULT if we try zero degrees of freedom
      float batch_chi_statistic_five_percent = -1.0;
      float batch_chi_statistic_one_percent = -1.0;
      
      if (num_batches > 1) {
        // look up the chi squared statistic for the 5% and 1% confidence levels
        batch_chi_statistic_five_percent = quantile(complement(chi_squared(num_batches-1), 0.05));
        batch_chi_statistic_one_percent = quantile(complement(chi_squared(num_batches-1), 0.01));
      }
#endif

      // get the total weight of the system
      int total_weight = 0;

      for (unsigned i = 0; i < per.size(); i++)
        total_weight += weight[i];

      // compute the expected number of objects stored per device in the absence of weighting
      float expected_objects = min(nr, num_devices_active) * num_objects;

      // compute each device's proportional weight
      vector<float> proportional_weights( per.size() );

      for (unsigned i = 0; i < per.size(); i++)
        proportional_weights[i] = (float) weight[i] / (float) total_weight;
      

#ifdef HAVE_BOOST_RANDOM_DISCRETE_DISTRIBUTION
      // create a random number generator with the device weights to use for simulating placements
      boost::random::discrete_distribution<> dist(proportional_weights);
#endif
      
      // compute the expected number of objects stored per device when a device's weight is considered
      vector<float> num_objects_expected(num_devices);

      for (unsigned i = 0; i < num_devices; i++)
        num_objects_expected[i] = (proportional_weights[i]*expected_objects);


      for (int currentBatch = 0; currentBatch < num_batches; currentBatch++) {
        if (currentBatch == (num_batches - 1)) {
          batch_max = max_x;
          objects_per_batch = (batch_max - batch_min + 1);
        }

        float batch_expected_objects = min(nr, num_devices_active) * objects_per_batch;
        vector<float> batch_num_objects_expected( per.size() );

        for (unsigned i = 0; i < per.size() ; i++)
          batch_num_objects_expected[i] = (proportional_weights[i]*batch_expected_objects);

        // create a vector to hold placement results temporarily 
        vector<int> temporary_per ( per.size() );

        for (int x = batch_min; x <= batch_max; x++) {

          // create a vector to hold the results of a CRUSH placement or RNG simulation
          vector<int> out;
          
          if (use_crush) {
            if (output_statistics)
              err << "CRUSH"; // prepend CRUSH to placement output
            crush.do_rule(r, x, out, nr, weight);
          } else {
            if (output_statistics)
              err << "RNG"; // prepend RNG to placement output to denote simulation

#ifdef HAVE_BOOST_RANDOM_DISCRETE_DISTRIBUTION
            // fill our vector with random numbers representing an OSD ID
            // one day we'll worry about duplicate entries, probably
            for (int j = 0; j < nr; j++)
              out.push_back( dist(gen) );
#endif
          }


          if (output_statistics)
            err << " rule " << r << " x " << x << " " << out << std::endl;
          for (unsigned i = 0; i < out.size(); i++) {
            per[out[i]]++;
            temporary_per[out[i]]++;
          }

          batchPer[currentBatch] = temporary_per;
          sizes[out.size()]++;

          if (output_bad_mappings && out.size() != (unsigned)nr) {
            cout << "bad mapping rule " << r << " x " << x << " num_rep " << nr << " result " << out << std::endl;
          }
        }

        // compute chi squared statistic for device examining the uniformity this batch of placements
         for (unsigned i = 0; i < per.size(); i++)
            deviceTestChi[i] += pow( (temporary_per[i] - batch_num_objects_expected[i]), 2) / batch_num_objects_expected[i];

         batch_min = batch_max + 1;
         batch_max = batch_min + objects_per_batch - 1;
      }
      
      for (unsigned i = 0; i < per.size(); i++)
        if (output_utilization && !output_statistics)
          err << "  device " << i
              << ":\t" << per[i]
              << std::endl;
      for (map<int,int>::iterator p = sizes.begin(); p != sizes.end(); p++)
        if ( output_statistics || p->first != nr)
          err << "rule " << r << " (" << crush.get_rule_name(r) << ") num_rep " << nr
              << " result size == " << p->first << ":\t"
              << p->second << "/" << (max_x-min_x+1) << std::endl;


#ifdef HAVE_BOOST_RANDOM_DISCRETE_DISTRIBUTION
      // compute our overall test chi squared statistic examining the final distribution of placements
      for (unsigned i = 0; i < per.size(); i++)
          if (num_objects_expected[i] > 0)
            test_chi_statistic += pow((num_objects_expected[i] - per[i]),2) / (float) num_objects_expected[i];

      int num_devices_failing_at_five_percent = 0;
      int num_devices_failing_at_one_percent = 0;
      
      for (unsigned i = 0; i < per.size(); i++) {
        if (deviceTestChi[i] > batch_chi_statistic_five_percent)
          num_devices_failing_at_five_percent++;
        if (deviceTestChi[i] > batch_chi_statistic_one_percent)
          num_devices_failing_at_one_percent++;
      }
#endif      

      if (output_statistics)
        for (unsigned i = 0; i < per.size(); i++) {
          if (output_utilization && num_batches > 1){
            if (num_objects_expected[i] > 0 && per[i] > 0) {
              err << "  device " << i << ":\t"
                  << "\t" << " stored " << ": " << per[i]
                  << "\t" << " expected " << ": " << num_objects_expected[i]
#ifdef HAVE_BOOST_RANDOM_DISCRETE_DISTRIBUTION
                  << "\t" << " X^2 " << ": " << deviceTestChi[i]
                  << "\t" << " critical (5% confidence) " << ": " << batch_chi_statistic_five_percent
                  << "\t" << " (1% confidence) " << ": " << batch_chi_statistic_one_percent
#endif
                  << std::endl;
            }
          } else if (output_utilization_all && num_batches > 1) {
            err << "  device " << i << ":\t"
                << "\t" << " stored " << ": " << per[i]
                << "\t" << " expected " << ": " << num_objects_expected[i]
#ifdef HAVE_BOOST_RANDOM_DISCRETE_DISTRIBUTION
                << "\t" << " X^2 " << ": " << deviceTestChi[i]
                << "\t" << " critical X^2 (5% confidence) " << ": " << batch_chi_statistic_five_percent
                << "\t" << " (1% confidence) " << ": " << batch_chi_statistic_one_percent
#endif
                << std::endl;
          }
        }

#ifdef HAVE_BOOST_RANDOM_DISCRETE_DISTRIBUTION
      err << " chi squared = " << test_chi_statistic
          << " (vs " << chi_statistic_five_percent << " / "
          << chi_statistic_one_percent
          << " for 5% / 1% confidence level) " << std::endl;
      if (output_utilization || output_utilization_all)
        err << " total system weight (dec) = " << (total_weight / (float) 0x10000) << std::endl;

      if (num_batches > 1 && output_statistics) {
        err << " " << num_devices_failing_at_five_percent << "/" << num_devices_active << " ("
            << (100.0*((float) num_devices_failing_at_five_percent / (float) num_devices_active))
            << "%) devices failed testing at 5% confidence level" << std::endl;
        err << " " << num_devices_failing_at_one_percent << "/" << num_devices_active  << " ("
            << (100.0*((float) num_devices_failing_at_one_percent / (float) num_devices_active))
            << "%) devices failed testing at 1% confidence level" << std::endl;
      }
#endif
    }
  }

  if (output_choose_tries) {
    __u32 *v;
    int n = crush.get_choose_profile(&v);
    for (int i=0; i<n; i++) {
      cout.setf(std::ios::right);
      cout << std::setw(2)
           << i << ": " << std::setw(9) << v[i];
      cout.unsetf(std::ios::right);
      cout << std::endl;
    }

    crush.stop_choose_profile();
  }

  return 0;
}
