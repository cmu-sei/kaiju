/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package kaiju.tools.ghihorn.frg;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.util.SystemUtilities;

import java.util.*;

import org.apache.commons.collections4.Factory;
import org.apache.commons.collections4.map.LazyMap;


public class FrgVertex {

	private Factory<List<CodeBlockReference>> factory = () -> new ArrayList<>();
	private Map<FrgVertex, List<CodeBlockReference>> incomingReferences = LazyMap.lazyMap(
		new HashMap<FrgVertex, List<CodeBlockReference>>(), factory);

	private Address address;

	public FrgVertex(Address address) {
		this.address = address;
	}

	public void addReference(FrgVertex referent, CodeBlockReference reference) {
		List<CodeBlockReference> refs = incomingReferences.get(referent);
		refs.add(reference);
	}

	public CodeBlockReference getReference(FrgVertex referent) {
		List<CodeBlockReference> refs = incomingReferences.get(referent);
		for (CodeBlockReference ref : refs) {
			Address destination = ref.getDestinationAddress();
			if (address.equals(destination)) {
				return ref;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return address.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((address == null) ? 0 : address.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		FrgVertex other = (FrgVertex) obj;
		return SystemUtilities.isEqual(address, other.address);
	}

	public Address getAddress() {
		return address;
	}

}
