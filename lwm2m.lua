do
        local lwm2m_proto = Proto("lwm2m", "LWM2M TLV decoding");

        local F_payload = ProtoField.bytes("lwm2m.payload", "Encoded TLV")
        local F_type = ProtoField.uint8("lwm2m.type", "Type")
        local F_lidentifier = ProtoField.uint8("lwm2m.lidentifier", "Identifier Length")
        local F_tlength = ProtoField.uint8("lwm2m.tlengthr", "Type of Length")
		local F_identifier = ProtoField.uint16("lwm2m.identifier", "Identifier")
		local F_length = ProtoField.uint32("lwm2m.length", "Length")	
		local F_value = ProtoField.bytes("lwm2m.value", "Value")
		local F_tlv = ProtoField.bytes("lwm2m.tlv", "TLV")

	
        lwm2m_proto.fields = {F_payload}         
        
        local f_payload = Field.new("coap.payload")
        local original_coap_dissector
        
        function lwm2m_proto.dissector(tvbuffer, pinfo, treeitem)
                
                original_coap_dissector:call(tvbuffer, pinfo, treeitem)
                if f_payload() then
                	start = 0
					buf_len = tvbuffer:len() - 1
					for i=0, buf_len do -- find the payload
						byte = tvbuffer (i, 1):uint()
						if byte == 255 then
							start = i + 1
							i = buf_len
						end
					end
			
					local subtreeitem = treeitem:add(lwm2m_proto, tvbuffer(start))
            		local lwm2mtreeitem = subtreeitem:add(F_payload, tvbuffer(start))
            		local i = start
            		while i< buf_len do
						byte = tvbuffer (i, 1):uint()
						i = i + 1
						tlvtype = bit32.band(byte, 0xc0)
						tlvtype = bit32.arshift(byte, 6)
						tlvtype_start = i - 1
						tlvtype_string = ""
						if tlvtype == 0 then
							tlvtype_string ="Object Instance TLV"
						end
						if tlvtype == 1 then
							tlvtype_string ="Resource Instance TLV"
						end
						if tlvtype == 2 then
							tlvtype_string ="Multiple Resource TLV"
						end
						if tlvtype == 3 then
							tlvtype_string ="Resource with value TLV"
						end
						l_identifier = bit32.band(byte, 0x20)
						l_identifier = bit32.arshift(l_identifier, 5)
						l_identifier_start = i - 1

						t_length = bit32.band(byte, 0x18)
						t_length = bit32.arshift(t_length, 3)
						t_length_start = i - 1
		
						if t_length == 0 then
							v_length = bit32.band(byte, 0x07)
							v_length_start = i - 1
							v_length_buf_len = 1
						end
						
						if l_identifier == 0 then
							identifier = tvbuffer (i, 1):uint()
							i = i + 1
							identifier_start = i - 1
							identifier_buf_len = 1
						end
						if l_identifier == 1 then
                    		identifier = tvbuffer (i, 2):uint()
                    		i = i + 2
                    		identifier_start = i - 2
                    		identifier_buf_len = 2					
						end
				
						if t_length == 1 then
							v_length = tvbuffer (i, 1):uint()
							i = i + 1
							v_length_start = i - 1
							v_length_buf_len = 1
						end
						if t_length == 2 then       
                    		v_length = tvbuffer (i, 2):uint()
                    		i = i + 2
                    		v_length_start = i - 2
							v_length_buf_len = 2
		                end
						if t_length == 3 then                        
				 			v_length = tvbuffer (i, 3):uint()
				 			i = i + 3
				 			v_length_start = i - 3
							v_length_buf_len = 3
		                end
						value = tvbuffer (i, v_length)
						i = i + v_length
				
						tlv_str = tlvtype_string.." - Identifier: "
						local tlv = lwm2mtreeitem:add(F_tlv, tvbuffer:range(tlvtype_start, i-tlvtype_start), identifier):set_text(tlv_str..identifier)
				
						tlv:add(F_type, tvbuffer:range(tlvtype_start, 1), tlvtype):set_text(tlvtype_string..": "..tlvtype)
						tlv:add(F_lidentifier, tvbuffer:range(l_identifier_start, 1), l_identifier):set_text("Identifier length: "..l_identifier)
						tlv:add(F_tlength, tvbuffer:range(t_length_start, 1), t_length):set_text("Type of length: "..t_length)
						tlv:add(F_length, tvbuffer:range(v_length_start, v_length_buf_len), v_length):set_text("Value Length: "..v_length)
						tlv:add(F_value, tvbuffer:range(i-v_length, v_length),  value):set_text("Value: "..value)

					end -- end while
                end -- end if payload
        end -- end dissector
        local udp_dissector_table = DissectorTable.get("udp.port")
        original_coap_dissector = udp_dissector_table:get_dissector(5683)
        udp_dissector_table:add(5683, lwm2m_proto)
end
