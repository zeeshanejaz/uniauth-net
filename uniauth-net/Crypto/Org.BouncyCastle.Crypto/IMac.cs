/***********************************************************************************************
* This license is an adaptation of the MIT X11 (http://opensource.org/licenses/mit-license.php) 
* License and should be read as such.
* 
* LICENSE
* Copyright (c) 2000 - 2011 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software
* and associated documentation files (the "Software"), to deal in the Software without
* restriction, including without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or
* substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
* BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
* DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 **********************************************************************************************/

namespace Org.BouncyCastle.Crypto
{
    /**
     * The base interface for implementations of message authentication codes (MACs).
     */
    internal interface IMac
    {
        /**
         * Initialise the MAC.
         *
         * @param param the key and other data required by the MAC.
         * @exception ArgumentException if the parameters argument is
         * inappropriate.
         */
        void Init(ICipherParameters parameters);

        /**
         * Return the name of the algorithm the MAC implements.
         *
         * @return the name of the algorithm the MAC implements.
         */
        string AlgorithmName { get; }

		/**
		 * Return the block size for this MAC (in bytes).
		 *
		 * @return the block size for this MAC in bytes.
		 */
		int GetMacSize();

        /**
         * add a single byte to the mac for processing.
         *
         * @param in the byte to be processed.
         * @exception InvalidOperationException if the MAC is not initialised.
         */
        void Update(byte input);

		/**
         * @param in the array containing the input.
         * @param inOff the index in the array the data begins at.
         * @param len the length of the input starting at inOff.
         * @exception InvalidOperationException if the MAC is not initialised.
         * @exception DataLengthException if there isn't enough data in in.
         */
        void BlockUpdate(byte[] input, int inOff, int len);

		/**
         * Compute the final stage of the MAC writing the output to the out
         * parameter.
         * <p>
         * doFinal leaves the MAC in the same state it was after the last init.
         * </p>
         * @param out the array the MAC is to be output to.
         * @param outOff the offset into the out buffer the output is to start at.
         * @exception DataLengthException if there isn't enough space in out.
         * @exception InvalidOperationException if the MAC is not initialised.
         */
        int DoFinal(byte[] output, int outOff);

		/**
         * Reset the MAC. At the end of resetting the MAC should be in the
         * in the same state it was after the last init (if there was one).
         */
        void Reset();
    }
}
