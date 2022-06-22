import React from 'react';
import styles from './EditableTypography.css'
const EditResume = ({edit, ...rest}) => {
    return (
        <>
            {edit ?
                <input  {...rest} className={`${styles.input} ${rest.className}`} />
                :
                <>
                    {rest.value}
                </>
            }
        </>
    );
};
export default EditResume