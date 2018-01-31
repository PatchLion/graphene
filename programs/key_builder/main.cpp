/*
 * Copyright (c) 2015 Cryptonomex, Inc., and contributors.
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include <fc/crypto/base58.hpp>
#include <fc/crypto/elliptic.hpp>
#include <fc/crypto/ripemd160.hpp>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <boost/program_options.hpp>
#include <graphene/utilities/key_conversion.hpp>
namespace bpo = boost::program_options;

int main(int argc, char** argv) {
	//std::cout << "AAAAAAAAAAAAAA" << "\n";
   fc::oexception unhandled_exception;
   try {
      bpo::options_description app_options("Graphene Key Builder");
      bpo::options_description cfg_options("Graphene Key Builder");
      app_options.add_options()
            ("help,h", "Print this help message and exit.")
            ("words,w", bpo::value<std::string>(), "Origin string.")
            ;

  
		bpo::variables_map options;
        try
      {
         bpo::options_description cli, cfg;
         app_options.add(cli);
         cfg_options.add(cfg);
         bpo::store(bpo::parse_command_line(argc, argv, app_options), options);
      }
      catch (const boost::program_options::error& e)
      {
        std::cerr << "Error parsing command line: " << e.what() << "\n";
        return 1;
      }
      if( options.count("help") )
      {
         std::cout << app_options << "\n";
         return 0;
      }

      if(!options.count("words") )
      {	 
         std::cout << app_options << "\n";
		 return -1;
      }
	
	  
      std::string origin_string = options["words"].as<std::string>();
	  
      auto created_key = fc::ecc::private_key::regenerate(fc::sha256::hash(origin_string));
	  std::cout << "WIF Key: " << graphene::utilities::key_to_wif(created_key) << "\n";
	  std::cout << "Public Key: " << created_key.get_public_key().to_base58()  << "\n";
      std::cout << "Secret: " << created_key.get_secret().str() << "\n";
	}
   catch ( const fc::exception& e )
   {
      std::cout << e.to_detail_string() << "\n";
      return -1;
   }
   return 0;
}