

use alloc::vec::Vec;
use das_core::util::load_witnesses;
use das_core::witness_parser::WitnessesParser;
use das_types::constants::DataType;
use crate::constants::MAX_WITNESS_SIZE;
use crate::debug_log;
use crate::error::Error;
use das_types::packed::{Data, DataEntity, DataEntityOpt, DeviceKey, DeviceKeyListCellData};
use das_types::prelude::Entity;

#[derive(Debug, Clone, Copy)]
struct DataIndex {
    start: usize,
    end: usize,
}
/*
    inner: use WitnessesParser to parse all witnesses then get the map
    inner_vec: all witnesses loaded data
    inner_used: inner_vec used size
    loaded_witness: map from DataType to DataIndex, maybe struct is better
 */
struct WitParser {
    inner: WitnessesParser,
    inner_vec: Vec<u8>,
    inner_used: usize,
    loaded_witness: Vec<(DataType, DataIndex)>,
}
static mut G_WIT_PARSER: Option<WitParser> = None;

impl WitParser {
    pub fn get() -> &'static mut Self {
        unsafe {
            match G_WIT_PARSER.as_mut() {
                Some(v) => v,
                None => {
                    G_WIT_PARSER = Some(Self::new());
                    G_WIT_PARSER.as_mut().unwrap()
                }
            }
        }
    }
    fn new() -> Self {
        let wp = match WitnessesParser::new(){
            Ok(v) => v,
            Err(e) => panic!("WitnessesParser::new() error: {:?}", e),
        };


        Self {
            inner: wp,
            inner_vec: Vec::with_capacity(MAX_WITNESS_SIZE), //maybe smaller than needed
            inner_used: 0,
            loaded_witness: Vec::new(),
        }

    }

    fn get_loaded_witness_index(
        &self,
        data_type: &DataType,
    )-> Option<DataIndex> {
        self.loaded_witness.iter().find(|(d, _)| d == data_type).map(|(_, i)| *i)
    }
    fn get_witness(
        &mut self,
        data_type: &DataType,
    )-> Result<&[u8], Error>{
        let index = match self.get_loaded_witness_index(&data_type){
            Some(v) => v,
            None => {
                self.load_witness(&data_type)?
            }
        };

        Ok(&self.inner_vec[index.start..index.end])
    }

    fn load_witness(
        &mut self,
        data_type: &DataType,
    )-> Result<DataIndex, Error>{
        let index = self.get_witness_index_by_data_type(data_type)?;
        let witness =  match load_witnesses(index) {
            Ok(v) => v,
            Err(e) => {
                debug_log!("load_witnesses error: {:?}", e);
                return Err(Error::LoadWitnessError);
            },
        };

        let start = self.inner_used;
        let end = self.inner_used + witness.len();
        if end > MAX_WITNESS_SIZE {
            return Err(Error::WitnessTooLarge);
        }
        //note: maybe zero copy is better
        self.inner_vec.extend_from_slice(&witness);
        self.loaded_witness.push((*data_type, DataIndex {
            start,
            end,
        }));
        self.inner_used += witness.len();

        Ok(DataIndex{
            start,
            end,
        })
    }
    fn get_witness_index_by_data_type(
        &self,
        data_type: &DataType,
    )-> Result<usize, Error> {
        let index = match self.inner.witnesses.iter().find(|(_, d)| d == data_type).map(|(i, _)| i){
            Some(v) => v,
            None => return Err(Error::WitnessNotFound),
        };
        Ok(*index)
    }
}


pub fn get_witness(
    data_type: &DataType,
)-> Result<&[u8], Error>{
    WitParser::get().get_witness(data_type)
}
pub fn get_pk_by_id_in_key_list(data: &[u8], pk_idx: usize) -> Result<Vec<u8>, Error> {
    //Warning: if there are differences between from_slice and from_compatible_slice
    let key_list = match DeviceKeyListCellData::from_slice(data){
        Ok(v) => v,
        Err(e) => {
            debug_log!("DeviceKeyListCellData::from_slice error: {:?}", e);
            return Err(Error::InvalidWitness);
        },
    };
    let mut payload = Vec::new();
    let keys_num = key_list.keys().len();
    if pk_idx >= keys_num {
        return Err(Error::InvalidWitness);
    }
    match key_list.keys().get(pk_idx) {
        None => {
            return Err(Error::InvalidWitness);
        }
        Some(k) => { payload.extend_from_slice(k.as_slice())}
    }
    Ok(payload)
}
//DeviceKeyListConfigCell parse
pub fn get_payload_by_pk_idx(pk_idx: usize) -> Result<Vec<u8>, Error> {
    //check if device key list cell exists in inputs
    //todo: need hash to check if the
    //todo add check if device key list cell exists in outputs
    let in_inputs = false;

    if in_inputs { //data_type_1 DeviceKeyListEntityData
        let witness = get_witness(&DataType::DeviceKeyListEntityData)?;
        let data = match Data::from_slice(&witness) {
            Ok(v) => v,
            Err(e) => {
                debug_log!("Data::from_slice error: {:?}", e);
                return Err(Error::InvalidWitness);
            },
        };
        //let mut payload = Vec::new();
        let data_entity_opt = data.old();
        if data_entity_opt.is_none() {
           return Err(Error::InvalidWitness);
        }
        let data_entity = match DataEntity::from_slice(&data_entity_opt.as_slice()){
            Ok(v) => v,
            Err(e) => {
                debug_log!("DataEntity::from_slice error: {:?}", e);
                return Err(Error::InvalidWitness);
            },
        };
        get_pk_by_id_in_key_list(&data_entity.entity().raw_data(), pk_idx)

    }else { //data_type_2 DeviceKeyListCellData
        let witness = get_witness(&DataType::DeviceKeyListCellData)?;
        get_pk_by_id_in_key_list(&witness, pk_idx)

    }
    // let witness = get_witness(&DataType::DeviceKeyListCellData)?;
    // let mut payload = Vec::new();
    // let mut offset = 0;
    // while offset < witness.len() {
    //     let pk_len = witness[offset] as usize;
    //     offset += 1;
    //     if pk_len == 0 {
    //         return Err(Error::InvalidWitness);
    //     }
    //     if offset + pk_len > witness.len() {
    //         return Err(Error::InvalidWitness);
    //     }
    //     if pk_idx == 0 {
    //         payload.extend_from_slice(&witness[offset..offset + pk_len]);
    //         break;
    //     }
    //     offset += pk_len;
    // }
    // Ok(payload)
}


//todo add subaccount support
